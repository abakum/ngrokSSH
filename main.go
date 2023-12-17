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
go get github.com/blacknon/go-sshlib
go get github.com/abakum/bnssh

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
	PORT    = "22"
	ALL     = "0.0.0.0"
	LH      = "127.0.0.1"
	TOS     = time.Second * 7
	TOM     = time.Millisecond * 7
	RFC2217 = 2217
	RFB     = 5900
	SOCKS5  = "1080"
	SSHD    = "2022"
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

	sp,
	hp,
	cwd,
	exe,
	image,
	publicURL,
	metadata,
	ln string
	userName = os.Getenv("USERNAME")

	err   error
	ips   []string
	count int

	sshd,
	ngrokOnline,
	ngrokSSHD,
	A bool

	sshdExe    = "sshd.exe"
	hub4comExe = "hub4com.exe"
	vncExes    = []string{"winvnc.exe", "tvnserver.exe", "winvnc4.exe", "vncserver.exe", "repeater.exe"}
	vncExe     = ""
	L, R       arrayFlags
)

func main() {

	defer closer.Close()
	closer.Bind(cleanup)

	cwd, err = os.Getwd()
	if err != nil {
		err = srcError(err)
		return
	}
	exe, err = os.Executable()
	if err != nil {
		err = srcError(err)
		return
	}
	image = filepath.Base(exe)

	flag.BoolVar(&A, "A", false, fmt.Sprintf("authentication `agent` forwarding as `ssh -A`\nuse `%s -A`", image))

	flag.Var(&L, "L", fmt.Sprintf("`local` port forwarding as `ssh -L [bh:]bp:dh:dp` or local socks5 proxy as `ssh -D [bh:]bp`\nuse `%s -L [bindHost:]bindPort[:dialHost:dialPort]` (default \"%s\")", image, SOCKS5))
	flag.Var(&R, "R", fmt.Sprintf("`remote` port forwarding as `ssh -R [dh:]dp:bh:bp` or remote socks5 proxy  as `ssh -R [bh:]bp`\nuse `%s -R [dialHost:]dialPort[:bindHost:bindPort]` (default \"%s\")", image, SOCKS5))

	flag.StringVar(&ln, "l", "", fmt.Sprintf("`login` name as `ssh -l ln` \nuse `%s -l ln host:port` or `%s ln@host:port`", image, image))
	flag.StringVar(&sp, "p", "", fmt.Sprintf("ssh `port` as `ssh -p port ln@host` or `sshd -p port` \nuse `%s -p port` or `%s -p port lh@host` (default \"%s\")", image, image, PORT))
	// if the ngorok tunnel has already been created or not access to api.ngrok.com, but a local sshd is needed, then use `ngrokSSH -d`
	// если туннель ngorok уже был создан или нет доступа к api.ngrok.com, но нужен локальный sshd, тогда используйте `ngrokSSH -d`
	// flag.BoolVar(&sshd, "d", false, fmt.Sprintf("ssh `daemon` mode - режим сервера ssh as `sshd -o listenaddress=host:port` if -d is omited then as `ssh host:port`\nuse `%s [-d] host:port` ", image))
	flag.Parse()
	hp = flag.Arg(0)
	if strings.Contains(hp, "@") {
		uhp := strings.Split(hp, "@")
		ln = uhp[0]
		hp = uhp[1]
	}
	h, p := SplitHostPort(hp, "", PORT) //lh->lh:22 22->:22
	h = strings.TrimPrefix(h, ALL)

	if sp != "" {
		p = sp
	}

	if h == "" && hp != "" && ln == "" {
		sshd = true
	}
	if ln != "" {
		userName = ln
	}
	hp = net.JoinHostPort(h, p)

	NGROK_AUTHTOKEN = Getenv("NGROK_AUTHTOKEN", NGROK_AUTHTOKEN) //create ngrok
	// NGROK_AUTHTOKEN += "-"                                       // emulate bad token or no internet
	// NGROK_AUTHTOKEN = ""                                         // emulate LAN mode
	NGROK_API_KEY = Getenv("NGROK_API_KEY", NGROK_API_KEY) //use ngrok
	// NGROK_API_KEY += "-"                                   // emulate LAN mode

	go established(image)
	count = psCount(image, "")

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
		err = sshTry(userName, h, p)
		if err == nil {
			client(userName, h, p, p)
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

type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, strings.TrimSpace(value))
	return nil
}
