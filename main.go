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
	"embed"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/abakum/winssh"
	"github.com/mitchellh/go-ps"
	"github.com/xlab/closer"
	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
)

const (
	PORT     = "22"
	ALL      = "0.0.0.0"
	LH       = "127.0.0.1"
	TOS      = time.Second * 7
	TOM      = time.Millisecond * 7
	RFC2217  = 2217
	RFB      = 5900
	USER     = 1024
	SOCKS5   = "1080"
	SSHD     = "2022"
	EMULATOR = "com0com - serial port emulator"
	BIN      = "bin"
	LIMIT    = "1"
	ITO      = "10"
	XO       = "on"
	DELAY    = "0.05"
)

var (
	//go:embed hostkey
	hostkey string

	//go:embed authorized_keys
	authorized_keys []byte

	//go:embed NGROK_AUTHTOKEN.txt
	NGROK_AUTHTOKEN string

	//go:embed NGROK_API_KEY.txt
	NGROK_API_KEY string

	//go:embed VERSION
	VERSION string

	//go:embed bin/*
	bin embed.FS

	sp,
	hp,
	cwd,
	exe,
	image,
	publicURL,
	metadata,
	ln,
	ser,
	sep,
	so,
	pair,
	CNCB,
	rfc2217,
	vnc,
	baud string

	err error
	ips []string

	sshd,
	ngrokOnline,
	ngrokSSHD,
	A,
	N bool

	sshdExe    = "sshd.exe"
	hub4comExe = "hub4com.exe"
	vncExes    = []string{"winvnc.exe", "tvnserver.exe", "winvnc4.exe", "vncserver.exe", "repeater.exe"}
	L, R       arrayFlags

	crypt    string
	hub4com  = `hub4com.exe`
	kitty    = `kitty_portable.exe`
	kittyINI = `kitty.ini`
	opts     = []string{"--baud=75"}
	ports    []*enumerator.PortDetails
	TO       = time.Second * 60

	hub *exec.Cmd
)

func main() {
	defer closer.Close()
	closer.Bind(cleanup)

	cwd, err = os.Getwd()
	if err != nil {
		err = srcError(err)
		return
	}

	err = fs.WalkDir(fs.FS(bin), BIN, func(unix string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		win := filepath.Join(append([]string{cwd}, strings.Split(unix, "/")...)...)
		if d.IsDir() {
			_, err = os.Stat(win)
			if err != nil {
				err = os.MkdirAll(win, 0666)
			}
			return err
		}
		bytes, err := bin.ReadFile(unix)
		if err != nil {
			return err
		}
		update := true
		switch path.Base(unix) {
		case hub4com:
			hub4com = win
		case kitty:
			kitty = win
		case kittyINI:
			kittyINI = win
			update = false
		}
		var size int64
		fi, err := os.Stat(win)
		if err == nil {
			size = fi.Size()
			if int64(len(bytes)) == size || !update {
				return nil
			}
		}
		ltf.Println(win, len(bytes), "->", size)
		return os.WriteFile(win, bytes, 0666)
	})
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

	ports, err = enumerator.GetDetailedPortsList()
	if err == nil && len(ports) > 0 {
		for _, sPort := range ports {
			// title := fmt.Sprintf("%s %s", sPort.Name, sPort.Product)
			com := strings.TrimPrefix(sPort.Name, "COM")
			if strings.HasPrefix(sPort.Product, EMULATOR) {
				if strings.HasPrefix(sPort.Product, EMULATOR+" CNC") {
					// Windows10
					p := string(strings.TrimPrefix(sPort.Product, EMULATOR+" CNC")[1])
					if pair == "" {
						pair = p
					}
					if pair != p {
						continue
					}
					if strings.HasPrefix(sPort.Product, EMULATOR+" CNCA") {
						// setupc install PortName=sPort.Name -
						sep = com
						CNCB = "CNCB" + pair
					} else {
						// setupc install PortName=COMserial PortName=sPort.Name
						CNCB = sPort.Name
						break
					}
				} else {
					// Windows7
					if sep == "" {
						sep = com
						CNCB = "CNCB0"
					} else {
						CNCB = sPort.Name
						break
					}
				}
			} else {
				sp, e := serial.Open(sPort.Name, &serial.Mode{})
				if e != nil {
					continue
				}
				_, e = sp.GetModemStatusBits()
				sp.Close()
				if e != nil {
					continue
				}
				// li.Println(title)
				if ser == "" {
					ser = com
				}
			}
		}
	}

	flag.BoolVar(&A, "A", false, fmt.Sprintf("authentication `agent` forwarding as `ssh -A`\nuse `%s -A`", image))

	flag.Var(&L, "L", fmt.Sprintf("`local` port forwarding as `ssh -L [bh:]bp:dh:dp` or local socks5 proxy as `ssh -D [bh:]bp`\nuse `%s -L [bindHost:]bindPort[:dialHost:dialPort]` (default \"%s\")", image, SOCKS5))
	flag.Var(&R, "R", fmt.Sprintf("`remote` port forwarding as `ssh -R [bh:]bp:dh:dp` or remote socks5 proxy  as `ssh -R [bh:]bp`\nuse `%s -R [bindHost:]bindPort[:dialHost:dialPort]` (default \"%s\")", image, SOCKS5))

	flag.StringVar(&ln, "l", "", fmt.Sprintf("`login` name as `ssh -l ln` \nuse `%s -l ln host:port` or `%s ln@host:port`", image, image))
	flag.StringVar(&sp, "p", "", fmt.Sprintf("ssh `port` as `ssh -p port ln@host` or `sshd -p port` \nuse `%s -p port` or `%s -p port lh@host` (default \"%s\")", image, image, PORT))
	// if the ngorok tunnel has already been created or not access to api.ngrok.com, but a local sshd is needed, then use `ngrokSSH -d`
	// если туннель ngorok уже был создан или нет доступа к api.ngrok.com, но нужен локальный sshd, тогда используйте `ngrokSSH -d`
	// flag.BoolVar(&sshd, "d", false, fmt.Sprintf("ssh `daemon` mode - режим сервера ssh as `sshd -o listenaddress=host:port` if -d is omited then as `ssh host:port`\nuse `%s [-d] host:port` ", image))

	flag.StringVar(&so, "s", "", fmt.Sprintf("`serial` port - последовательный порт\nuse `%s -serial port`", image))
	flag.StringVar(&rfc2217, "t", "", fmt.Sprintf("serial over `telnet` daemon RFC2217 - сервер последовательного порта\nuse `%s -rfc2217 [bh:]bp:dh:dp`", image))
	flag.StringVar(&vnc, "v", "", fmt.Sprintf("`VNC` daemon - сервер VNC\nuse `%s -vnc [bh:]bp:dh:dp`", image))
	flag.StringVar(&baud, "b", "", fmt.Sprintf("serial `baud` - скорость последовательного порта\nuse `%s -baud baud`", image))
	flag.BoolVar(&N, "N", false, fmt.Sprintf("force `ngrok` mode - не пробовать подключаться локально\nuse `%s -N`", image))

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
	hp = net.JoinHostPort(h, p)

	NGROK_AUTHTOKEN = Getenv("NGROK_AUTHTOKEN", NGROK_AUTHTOKEN) //create ngrok
	// NGROK_AUTHTOKEN += "-"                                       // emulate bad token or no internet
	// NGROK_AUTHTOKEN = ""                                         // emulate LAN mode
	NGROK_API_KEY = Getenv("NGROK_API_KEY", NGROK_API_KEY) //use ngrok

	if psCount(image, "") != 1 {
		li.Println("another one has been launched - запущен ещё один", image)
	}

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
		err = sshTry(un(""), h, p)
		if err == nil {
			client(un(""), h, p, p)
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

func interfaces() (ips []string) {
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
				ips = append(ips, strings.Split(addr.String(), "/")[0])
			}
		}
		slices.Reverse(ips)
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

func cmd(s string, c *exec.Cmd) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf(`%s "%s" %s`, s, c.Args[0], strings.Join(c.Args[1:], " "))
}
