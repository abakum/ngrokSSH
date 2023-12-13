/*
git clone https://github.com/abakum/ngrokSSH
go mod init github.com/abakum/ngrokSSH
go get github.com/abakum/go-console
go get github.com/abakum/winssh

go get github.com/gliderlabs/ssh
go get github.com/pkg/sftp
go get golang.ngrok.com/ngrok
go get github.com/ngrok/ngrok-api-go/v5
go get github.com/abakum/go-netstat
go get github.com/mitchellh/go-ps

go mod tidy
*/
package main

import (
	_ "embed" //no lint
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/abakum/winssh"
	"github.com/mitchellh/go-ps"
	"github.com/xlab/closer"
)

const (
	PORT = "22"
	ALL  = "0.0.0.0"
	LH   = "127.0.0.1"
	TOS  = time.Second * 7
	TOM  = time.Millisecond * 7
)

var (
	//go:embed authorized_keys
	authorized_keys []byte

	//go:embed NGROK_AUTHTOKEN.txt
	NGROK_AUTHTOKEN string

	//go:embed NGROK_API_KEY.txt
	NGROK_API_KEY string

	//go:embed VERSION
	VERSION string

	sshPort,
	hp,
	cwd,
	exe,
	imagename,
	ifs,
	publicURL,
	metadata string
	err   error
	ips   []string
	count int
	sshd,
	ngrokOnline,
	ngrokSSHD bool
	sshdExe = "sshd.exe"
)

func main() {
	defer closer.Close()
	closer.Bind(cleanup)

	// if the ngorok tunnel has already been created or not acces to api.ngrok.com, but a local sshd is needed, then use `ngrokSSH -d`
	// если туннель ngorok уже был создан или нет доступа к api.ngrok.com, но нужен локальный sshd, тогда используйте `ngrokSSH -d`
	flag.BoolVar(&sshd, "d", false, "ssh `daemon` mode - режим сервера ssh\nuse `"+imagename+" -d host:port` as `sshd -o listenaddress=host:port`")

	flag.StringVar(&sshPort, "p", "", fmt.Sprintf("ssh `port`\nuse `"+imagename+" -p port` as `ssh -p port` or `sshd -p port` (default \"%s\")", PORT))

	flag.Parse()
	hp = flag.Arg(0)
	h, p, e := net.SplitHostPort(hp)
	if e != nil {
		h = hp
	}
	h = strings.TrimPrefix(h, ALL)

	if sshPort != "" {
		p = sshPort
	}
	if p == "" {
		p = PORT
	}

	if h == "" && hp != "" {
		sshd = true
	}
	hp = net.JoinHostPort(h, p)
	ltf.Println(hp, sshd)

	cwd, err = os.Getwd()
	if err != nil {
		return
	}

	NGROK_AUTHTOKEN = Getenv("NGROK_AUTHTOKEN", NGROK_AUTHTOKEN) //create ngrok
	// NGROK_AUTHTOKEN += "-"                                       // emulate bad token or no internet
	// NGROK_AUTHTOKEN = ""                                         // emulate LAN mode
	NGROK_API_KEY = Getenv("NGROK_API_KEY", NGROK_API_KEY) //use ngrok
	// NGROK_API_KEY += "-"                                   // emulate LAN mode

	exe, err = os.Executable()
	if err != nil {
		err = srcError(err)
		return
	}
	imagename = filepath.Base(exe)
	go established(imagename)
	count = psCount(imagename, "")

	ips = interfaces()
	if len(ips) == 0 {
		err = srcError(fmt.Errorf("not connected - нет сети"))
		return
	}
	li.Println(ips)

	publicURL, metadata, err = ngrokAPI(NGROK_API_KEY)
	PrintOk(publicURL+" "+metadata, err)

	ngrokSSHD = err == nil
	ngrokOnline = ngrokSSHD
	if !ngrokSSHD {
		ngrokOnline = strings.HasSuffix(err.Error(), "not found online client")
	}
	if sshd {
		server()
		return
	}
	if h != "" {
		u := os.Getenv("USERNAME")
		err = sshTry(u, h, p)
		if err == nil {
			client(u, h, p)
			return
		}
	}
	if ngrokSSHD {
		client(fromNgrok(publicURL, metadata))
		return
	}
	server()
}

func psCount(name, parent string) (count int) {
	pes, err := ps.Processes()
	if err != nil {
		return
	}
	for _, p := range pes {
		if p == nil {
			continue
		}
		ok := true
		if parent != "" {
			pp, err := ps.FindProcess(p.PPid())
			if pp == nil || err != nil {
				continue
			}
			ok = pp.Executable() == parent
		}
		if p.Executable() == name && ok {
			count++
		}
	}
	return
}

func interfaces() (ifs []string) {
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, ifac := range ifaces {
			addrs, err := ifac.Addrs()
			if err != nil || ifac.Flags&net.FlagUp == 0 || ifac.Flags&net.FlagRunning == 0 || ifac.Flags&net.FlagLoopback != 0 {
				continue
			}
			for _, addr := range addrs {
				if strings.Contains(addr.String(), ":") {
					continue
				}
				ifs = append(ifs, strings.Split(addr.String(), "/")[0])
			}
		}
		slices.Reverse(ifs)
	}
	return
}

func cleanup() {
	if err != nil {
		let.Println(err)
		defer os.Exit(1)
	}
	winssh.AllDone(os.Getpid())
}
