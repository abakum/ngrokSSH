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
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/abakum/proxy"
	"github.com/abakum/winssh"
	"github.com/dixonwille/wmenu/v5"
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
	RFC2217  = 2217
	RFB      = 5900
	EMULATOR = "com0com - serial port emulator"
	ROOT     = "bin"
	LIMIT    = "1"
	ITO      = "10"
	XO       = "on"
	DELAY    = "0.05"
	HUB4COM  = "hub4com.exe"
	KITTY    = "kitty_portable.exe"
	REALVV   = "vncviewer.exe"
	CGIV     = "-V"
	CGIT     = "-T"
	MENUT    = "Choose target for console - выбери цель подключения консоли через `RFC2217`"
)

var (
	//go:embed NGROK_AUTHTOKEN.txt
	NgrokAuthToken string

	//go:embed NGROK_API_KEY.txt
	ngrokApiKey string

	//go:embed VERSION
	Ver string

	//go:embed bin/hub4com.exe bin/kitty_portable.exe bin/kitty.ini bin/Sessions/Default%20Settings bin/Proxies/* bin/vncaddrbook.exe bin/AB/* bin/vncviewer.exe
	Bin embed.FS

	//go:embed bin/known_host
	Known_host string

	Hp,
	Cwd,
	Exe,
	Image,
	PublicURL,
	Ln,
	So,
	Cncb,
	Rfc2217,
	Vnc,
	Baud,
	S,
	OpenSSH string

	Err error
	Ips []string

	NgrokOnline,
	NgrokSSHD,
	A,
	N,
	O bool

	VncExes = []string{"winvnc.exe", "tvnserver.exe", "winvnc4.exe", "vncserver.exe", "repeater.exe"}
	L,
	R,
	V,
	T,
	C,
	Coms arrayFlags

	Crypt       string
	Hub         *exec.Cmd
	Fns         map[string]string
	MenuToption []string
	MenuTid     = 0
)

func main() {
	const (
		SOCKS5          = "1080"
		NGROK_AUTHTOKEN = "NGROK_AUTHTOKEN"
		NGROK_API_KEY   = "NGROK_API_KEY"
	)
	var (
		metadata,
		sp string
		err  error
		sshd bool
	)

	Cwd, Err = os.Getwd()
	if Err != nil {
		letf.Fatal(Err)
	}
	proxy.RealAddrBook(filepath.Join(Cwd, ROOT, REALVV))
	Exe, Err = os.Executable()
	if Err != nil {
		letf.Fatal(Err)
	}

	Known_host = strings.TrimSpace(Known_host)
	defer closer.Close()
	closer.Bind(cleanup)

	Image = filepath.Base(Exe)
	Fns, _ = UnloadEmbedded(Bin, ROOT, Cwd, ROOT, true)

	Coms, So, Cncb = GetDetailedPortsList()
	Cncb = `\\.\` + Cncb

	flag.BoolVar(&A, "A", false, fmt.Sprintf("authentication `agent` forwarding as - перенос авторизации как `ssh -A`\nuse `%s -A`", Image))

	flag.Var(&C, "C", fmt.Sprintf("`COM` port for daemon of serial server - порт для сервера \nuse `%s -C port`", Image))
	flag.Var(&L, "L", fmt.Sprintf("`local` port forwarding as - перенос через ближний порт как `ssh -L [bh:]bp:dh:dp` or local socks5 proxy as `ssh -D [bh:]bp`\nuse `%s -L [bindHost:]bindPort[:dialHost:dialPort]`", Image))
	flag.BoolVar(&N, "N", false, fmt.Sprintf("force `ngrok` mode - не пробовать подключаться локально\nuse `%s -N`", Image))
	OpenSSH, err = exec.LookPath("ssh")
	if err == nil {
		flag.BoolVar(&O, "O", false, fmt.Sprintf("use ssh from `OpenSSH` - использовать `%s` вместо `%s` \nuse `%s -O`", OpenSSH, Fns[KITTY], Image))
	}
	flag.Var(&R, "R", fmt.Sprintf("`remote` port forwarding as - перенос через дальний порт как `ssh -R [bh:]bp:dh:dp` or remote socks5 proxy  as `ssh -R [bh:]bp`\nuse `%s -R [bindHost:]bindPort[:dialHost:dialPort]`", Image))
	flag.StringVar(&S, "S", SOCKS5, fmt.Sprintf("port for proxy - порт для прокси `Socks5`\nuse `%s -S port`", Image))
	flag.Var(&T, "T", fmt.Sprintf("local port forwarding for serial console over - перенос через ближний порт для последовательной консоли через `telnet` RFC2217 like -L\nuse `%s -T [bindHost:]bindPort[:dialHost:dialPort]`", Image))
	flag.Var(&V, "V", fmt.Sprintf("local port forwarding for - перенос через ближний порт для `VNC` like -L\nuse `%s -V [bindHost:]bindPort[:dialHost:dialPort]`", Image))

	flag.StringVar(&Baud, "b", "", fmt.Sprintf("serial console `baud` - скорость последовательной консоли\nuse `%s -b baud`", Image))
	flag.StringVar(&Ln, "l", "", fmt.Sprintf("`login` name as `ssh -l ln` \nuse `%s -l ln host:port` or `%s ln@host:port`", Image, Image))
	flag.StringVar(&sp, "p", "", fmt.Sprintf("ssh `port` as `ssh -p port ln@host` or `sshd -p port` \nuse `%s -p port` or `%s -p port lh@host` (default \"%s\")", Image, Image, PORT))
	// if the ngorok tunnel has already been created or not access to api.ngrok.com, but a local sshd is needed, then use `ngrokSSH -d`
	// если туннель ngorok уже был создан или нет доступа к api.ngrok.com, но нужен локальный sshd, тогда используйте `ngrokSSH -d`
	// flag.BoolVar(&sshd, "d", false, fmt.Sprintf("ssh `daemon` mode - режим сервера ssh as `sshd -o listenaddress=host:port` if -d is omited then as `ssh host:port`\nuse `%s [-d] host:port` ", image))

	flag.StringVar(&So, "s", So, fmt.Sprintf("`serial` port for console - последовательный порт для консоли\nuse `%s -s port`", Image))
	// flag.StringVar(&Rfc2217, "t", "", fmt.Sprintf("serial over `telnet` daemon RFC2217 - сервер последовательного порта\nuse `%s -rfc2217 [bh:]bp:dh:dp`", Image))
	// flag.StringVar(&Vnc, "v", "", fmt.Sprintf("`VNC` daemon - сервер VNC\nuse `%s -vnc [bh:]bp:dh:dp`", Image))
	flag.Parse()

	if len(C) == 0 {
		C = Coms[:]
	}

	Hp = flag.Arg(0)
	if strings.Contains(Hp, "@") {
		uhp := strings.Split(Hp, "@")
		Ln = uhp[0]
		Hp = uhp[1]
	}

	h, p := SplitHostPort(Hp, "", PORT) //lh->lh:22 22->:22
	h = strings.TrimPrefix(h, ALL)

	if sp != "" {
		p = sp
	}

	if h == "" && Hp != "" && Ln == "" {
		sshd = true
	}
	Hp = net.JoinHostPort(h, p)

	NgrokAuthToken = Getenv(NGROK_AUTHTOKEN, NgrokAuthToken) //create ngrok
	// NgrokAuthToken += "-"                                       // emulate bad token or no internet
	// NgrokAuthToken = ""                                         // emulate LAN mode
	ngrokApiKey = Getenv(NGROK_API_KEY, ngrokApiKey) //use ngrok

	if psCount(Image, "", 0) != 1 {
		li.Println("another one has been launched - запущен ещё один", Image)
	}

	// is hub4com running local?
	if len(T) > 0 && So != "" {
		for _, opt := range T {
			hphp := parseHPHP(opt, RFC2217)
			p, err := strconv.Atoi(hphp[1])
			if err == nil && isListen(hphp[0], p, 0) {
				//hub4com running local
				MenuToption = append(MenuToption, strings.Join(hphp, ":"))
			}
			if len(MenuToption) > 0 {
				VisitAll("")
				li.Println("local mode serial console  - локальный режим последовательной консоли")
				if len(MenuToption) == 1 {
					tty(parseHPHP(MenuToption[0], RFC2217)...)
					return
				}
				for {
					menuT := wmenu.NewMenu(MENUT)
					menuT.Action(func(opts []wmenu.Opt) error {
						for _, opt := range opts {
							MenuTid = opt.ID
							tty(parseHPHP(opt.Text, RFC2217)...)
							return nil
						}
						return nil
					})
					for i, opt := range MenuToption {
						menuT.Option(opt, nil, i == MenuTid, nil)
					}
					if menuT.Run() != nil {
						return
					}
				}
			}
		}
	}

	Ips = interfaces()
	if len(Ips) == 0 {
		Err = srcError(fmt.Errorf("not connected - нет сети"))
		return
	}
	li.Println(Ips)

	PublicURL, metadata, Err = ngrokAPI(ngrokApiKey)
	PrintOk(PublicURL+" "+metadata, Err)
	NgrokSSHD = Err == nil
	NgrokOnline = NgrokSSHD
	if !NgrokSSHD {
		NgrokOnline = strings.HasSuffix(Err.Error(), "not found online client")
	}

	if sshd {
		server()
		return
	}
	if h != "" {
		Err = sshTry(un(""), h, p)
		if Err == nil {
			client(un(""), h, p, p)
			return
		}
	}
	if NgrokSSHD {
		client(fromNgrok(PublicURL, metadata))
		return
	}
	server()
}

func psCount(name, parent string, ppid int) (count int) {
	pes, err := ps.Processes()
	if err != nil {
		return
	}
	for _, p := range pes {
		if p == nil {
			continue
		}
		ok := true
		if ppid == 0 {
			ok = parent == ""
			if !ok {
				pp, err := ps.FindProcess(p.PPid())
				ok = err != nil && pp != nil && pp.Executable() == parent
			}
		} else {
			ok = p.PPid() == ppid
		}
		if ok && p.Executable() == name {
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
	if Err != nil {
		let.Println(Err)
		defer os.Exit(1)
	}
	winssh.AllDone(os.Getpid())
}

type arrayFlags []string

func (i *arrayFlags) String() string {
	return fmt.Sprintf("%v", *i)
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, strings.TrimSpace(strings.ReplaceAll(value, "*", ALL)))
	return nil
}

func cmd(s string, c *exec.Cmd) string {
	if c == nil {
		return ""
	}
	return fmt.Sprintf(`%s "%s" %s`, s, c.Args[0], strings.Join(c.Args[1:], " "))
}

func actual(fs *flag.FlagSet, fn string) bool {
	return reflect.Indirect(reflect.ValueOf(fs)).FieldByName("actual").MapIndex(reflect.ValueOf(fn)).IsValid()
}

func def(manual, auto string) string {
	if manual == "" {
		return auto
	}
	return manual
}

func GetDetailedPortsList() (coms arrayFlags, seTTY, cncb string) {
	ports, err := enumerator.GetDetailedPortsList()
	if err != nil || len(ports) == 0 {
		return
	}
	pair := ""
	for _, port := range ports {
		// title := fmt.Sprintf("%s %s", sPort.Name, sPort.Product)
		com := strings.TrimPrefix(port.Name, "COM")
		if strings.HasPrefix(port.Product, EMULATOR) {
			if strings.HasPrefix(port.Product, EMULATOR+" CNC") {
				// Windows10
				p := string(strings.TrimPrefix(port.Product, EMULATOR+" CNC")[1])
				if pair == "" {
					pair = p
				}
				if pair != p {
					continue
				}
				if strings.HasPrefix(port.Product, EMULATOR+" CNCA") {
					// setupc install PortName=sPort.Name -
					seTTY = com
					cncb = "CNCB" + pair
				} else {
					// setupc install PortName=COMserial PortName=sPort.Name
					cncb = port.Name
					break
				}
			} else {
				// Windows7
				if seTTY == "" {
					seTTY = com
					cncb = "CNCB0"
				} else {
					cncb = port.Name
					break
				}
			}
		} else {
			//server serial
			sp, err := serial.Open(port.Name, &serial.Mode{})
			if err != nil {
				continue
			}
			_, err = sp.GetModemStatusBits()
			sp.Close()
			if err != nil {
				continue
			}
			//serial not in use
			// li.Println(title)
			coms = append(coms, com)
		}
	}
	return
}

/*
copy from embed

src - name of dir was embed

root - root dir for target

trg - target dir

keep == true if not exist then write

keep == false it will be replaced if it differs from the embed
*/
func UnloadEmbedded(bin embed.FS, src, root, trg string, keep bool) (fns map[string]string, err error) {
	fns = make(map[string]string)
	srcLen := strings.Count(src, "/")
	if i := strings.Count(src, `\`); i > srcLen {
		srcLen = i
	}
	srcLen++
	dirs := append([]string{root}, strings.Split(trg, `\`)...)
	write := func(unix string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		win := filepath.Join(append(dirs, strings.Split(unix, "/")[srcLen:]...)...)
		fns[strings.TrimPrefix(unix, src+"/")] = win
		if d.IsDir() {
			_, err = os.Stat(win)
			if err != nil {
				err = os.MkdirAll(win, 0755)
			}
			return err
		}
		bytes, err := bin.ReadFile(unix)
		if err != nil {
			return err
		}
		var size int64
		fi, err := os.Stat(win)
		if err == nil {
			size = fi.Size()
			if int64(len(bytes)) == size || keep {
				return nil
			}
		}
		li.Println(win, len(bytes), "->", size)
		return os.WriteFile(win, bytes, 0644)
	}
	err = fs.WalkDir(fs.FS(bin), src, write)
	return
}
