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
	"bytes"
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

	"github.com/abakum/proxy"
	"github.com/abakum/winssh"
	"github.com/dixonwille/wmenu/v5"
	gl "github.com/gliderlabs/ssh"
	"github.com/mitchellh/go-ps"
	"github.com/xlab/closer"
	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
	"golang.org/x/crypto/ssh"
)

const (
	PORT            = "22"
	ALL             = "0.0.0.0"
	LH              = "127.0.0.1"
	RFC2217         = 2217
	RFB             = 5900
	EMULATOR        = "com0com - serial port emulator"
	ROOT            = "bin"
	LIMIT           = "1"
	ITO             = "10"
	XO              = "on"
	DELAY           = "0.05"
	HUB4COM         = "hub4com.exe"
	KITTY           = "kitty_portable.exe"
	REALVV          = "vncviewer.exe"
	CGIV            = "-v"
	CGIT            = "-t"
	MENU            = "Choose target for console - выбери цель подключения консоли"
	FiLEMODE        = 0644
	DIRMODE         = 0755
	KNOWN_HOSTS     = "known_hosts.ini"     //created on first run
	AUTHORIZED_KEYS = "authorized_keys.ini" //created on first run
)

var (
	//go:embed NGROK_AUTHTOKEN.txt
	NgrokAuthToken string

	//go:embed NGROK_API_KEY.txt
	ngrokApiKey string

	//go:embed VERSION
	Ver string

	//go:embed bin/*.exe bin/*.ini bin/Sessions/Default%20Settings bin/Proxies/1080 bin/AB/*
	Bin embed.FS

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
	OpenSSH,
	AuthorizedKeysIni,
	KnownHosts string

	Err error

	NgrokOnline,
	NgrokSSHD,
	A,
	N,
	O,
	h bool

	L,
	R,
	V,
	T,
	C,
	Coms arrayFlags

	Crypt string
	Hub   *exec.Cmd
	Fns   map[string]string
	MenuToption,
	Ips []string
	MenuTid = 0
	Signer  gl.Signer
	KnownKeys,
	AuthorizedKeys []ssh.PublicKey
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
		err error
	)
	// cgi
	if len(os.Args) == 2 {
		ret, res := tv(os.Args[1])
		if ret {
			fmt.Print(res)
			return
		}
	}

	Cwd, Err = os.Getwd()
	if Err != nil {
		letf.Fatal(Err)
	}
	proxy.RealAddrBook(filepath.Join(Cwd, ROOT, REALVV))

	Exe, Err = os.Executable()
	if Err != nil {
		letf.Fatal(Err)
	}
	proxy.RealSet("", "")

	Image = filepath.Base(Exe)

	Fns, _ = UnloadEmbedded(Bin, ROOT, Cwd, ROOT, true)

	pri := winssh.GetHostKey(Cwd)
	pemBytes, Err := os.ReadFile(pri)
	if Err != nil {
		Signer, Err = winssh.GenerateSigner(pri)
	} else {
		Signer, Err = ssh.ParsePrivateKey(pemBytes)
	}
	if Err != nil {
		letf.Fatal(Err)
	}
	pubKey := Signer.PublicKey()
	li.Println("HostKey", FingerprintSHA256(pubKey))
	rest := append([]byte("* "), ssh.MarshalAuthorizedKey(pubKey)...)
	KnownHosts = filepath.Join(Cwd, ROOT, KNOWN_HOSTS)
	_, err = os.Stat(KnownHosts)
	if os.IsNotExist(err) {
		PrintOk("WriteFile "+KnownHosts, os.WriteFile(KnownHosts, rest, FiLEMODE))
	}

	AuthorizedKeysIni = filepath.Join(Cwd, ROOT, AUTHORIZED_KEYS)
	for _, name := range winssh.GetUserKeysPaths(Cwd, AuthorizedKeysIni) {
		AuthorizedKeys = FileToAuthorized(name, AuthorizedKeys)
	}
	_, err = os.Stat(AuthorizedKeysIni)
	if os.IsNotExist(err) && len(AuthorizedKeys) > 0 {
		PrintOk("WriteFile "+AuthorizedKeysIni, os.WriteFile(AuthorizedKeysIni, MarshalAuthorizedKeys(AuthorizedKeys...), FiLEMODE))
	}

	rest, err = os.ReadFile(KnownHosts)
	if err != nil {
		letf.Println(err)
	} else {
		var (
			hosts  []string
			pubKey ssh.PublicKey
		)
		for {
			_, hosts, pubKey, _, rest, err = ssh.ParseKnownHosts(rest)
			if err != nil {
				break
			}
			if len(hosts) > 0 && hosts[0] == "*" {
				ltf.Println(FingerprintSHA256(pubKey))
				KnownKeys = append(KnownKeys, pubKey)
			}
		}
	}

	Coms, So, Cncb = GetDetailedPortsList()
	Cncb = `\\.\` + Cncb

	flag.BoolVar(&A, "A", false, fmt.Sprintf("authentication `agent` forwarding as - перенос авторизации как `ssh -A`\nexample - пример `%s -A`", Image))

	flag.Var(&C, "C", fmt.Sprintf("`COM` serial port for daemon - последовательный порт для сервера `hub4com`\nexample - пример `%s -C 7`", Image))
	flag.Var(&L, "L", fmt.Sprintf("`local` port forwarding as - перенос ближнего порта как `ssh -L [bindHost:]bindPort[:dialHost:dialPort]` or\nlocal socks5 proxy as `ssh -D [bindHost:]bindPort`\nexample - пример `%s -L 80:0.0.0.0:80`", Image))
	flag.BoolVar(&N, "N", false, fmt.Sprintf("force `ngrok` mode - не пробовать подключаться локально\nexample - пример `%s -N`", Image))
	OpenSSH, err = exec.LookPath("ssh")
	if err == nil {
		flag.BoolVar(&O, "O", false, fmt.Sprintf("use ssh from `OpenSSH` - использовать `%s` вместо `%s`\nexample - пример `%s -O`", OpenSSH, Fns[KITTY], Image))
	} else {
		ltf.Println("OpenSSH not found")
	}

	flag.Var(&R, "R", fmt.Sprintf("`remote` port forwarding as - перенос дальнего порта как `ssh -R [bindHost:]bindPort:dialHost:dialPort` or\nremote socks5 proxy  as `ssh -R [bindHost:]bindPort`\nexample - пример `%s -R *:80::80`", Image))
	flag.StringVar(&S, "S", SOCKS5, fmt.Sprintf("port for proxy - порт для прокси `Socks5`\nexample - пример `%s -S 8080`", Image))
	flag.Var(&T, "T", fmt.Sprintf("local port forwarding for serial console over - перенос ближнего порта для последовательной консоли через `telnet` RFC2217 like -L\nexample - пример `%s -T 192.168.0.1:7000`", Image))
	flag.Var(&V, "V", fmt.Sprintf("local port forwarding for - перенос ближнего порта для `VNC` like -L\nexample - пример  `%s -V 5901`", Image))

	flag.StringVar(&Baud, "b", "", fmt.Sprintf("serial console `baud` - скорость последовательной консоли\nexample - пример `%s -b 9600`", Image))
	flag.BoolVar(&h, "h", h, fmt.Sprintf("show `help` for usage - показать использование параметров\nexample - пример `%s -h`", Image))
	flag.StringVar(&Ln, "l", "", fmt.Sprintf("`login` name as `ssh -l ln`\nexample - пример `%s -l root 192.168.0.1:2222` or `%s root@192.168.0.1:2222`", Image, Image))
	flag.StringVar(&sp, "p", PORT, fmt.Sprintf("ssh `port` as `ssh -p port ln@host` or `sshd -p port`\nexample - пример `%s -p 2222` or `%s -p 2222 root@192.168.0.1`", Image, Image))

	flag.StringVar(&So, "s", So, fmt.Sprintf("`serial` port for console - последовательный порт для консоли\nexample - пример `%s -s 11`", Image))
	flag.Parse()
	if h {
		fmt.Printf("Usage of %s version %s:\n", Image, Ver)
		flag.PrintDefaults()
		return
	}
	if !actual(flag.CommandLine, "V") {
		V.Set("")
	}
	if !actual(flag.CommandLine, "T") {
		T.Set("")
	}

	defer closer.Close()
	closer.Bind(cleanup)

	if len(C) == 0 {
		C = Coms[:]
	}
	arg := flag.Arg(0)
	Hp = arg
	if strings.Contains(arg, "@") {
		uhp := strings.Split(arg, "@")
		Ln = uhp[0]
		if len(uhp) > 1 {
			Hp = uhp[1]
		}
	}

	h, p := SplitHostPort(Hp, LH, sp)
	Hp = net.JoinHostPort(h, p)
	// li.Fatalln("arg", arg, "Ln", Ln, "Hp", Hp)

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
					menuT := wmenu.NewMenu(MENU)
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

	// local server:
	// args!="" && loginName==""
	// ngrokSSH `*` as `0.0.0.0:22`
	// ngrokSSH `:` as `127.0.0.1:22`
	// ngrokSSH `@` as `127.0.0.1:22`
	// ngrokSSH `-p 2222` as `127.0.0.1:2222`
	if Ln == "" && (arg != "" || actual(flag.CommandLine, "p")) {
		server()
		return
	}

	// local client:
	// loginName!=""
	if Ln != "" {
		ltf.Println("try by param")
		Err = sshTry(un(""), h, p)
		if Err == nil {
			client(un(""), h, p, p)
			return
		}
	}

	// client:
	// args=="" || loginName!=""
	if NgrokSSHD {
		client(fromNgrok(PublicURL, metadata))
		return
	}
	server()
}

func aKey() {

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
			if os.IsNotExist(err) {
				err = os.MkdirAll(win, DIRMODE)
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
		return os.WriteFile(win, bytes, FiLEMODE)
	}
	err = fs.WalkDir(fs.FS(bin), src, write)
	return
}

// ParseAuthorizedKeys
func FileToAuthorized(name string, in []ssh.PublicKey) (authorized []ssh.PublicKey) {
	authorized = in[:]
	rest, err := os.ReadFile(name)
	if err != nil {
		return
	}
	var out ssh.PublicKey
	for {
		out, _, _, rest, err = ssh.ParseAuthorizedKey(rest)
		if err != nil {
			return
		}
		found := false
	uniq:
		for _, old := range authorized {
			found = bytes.Equal(old.Marshal(), out.Marshal())
			if found {
				break uniq
			}
		}
		if !found {
			ltf.Println(name, FingerprintSHA256(out))
			authorized = append(authorized, out)
		}
	}
}

func MarshalAuthorizedKeys(AuthorizedKeys ...ssh.PublicKey) []byte {
	b := &bytes.Buffer{}
	for _, pubKey := range AuthorizedKeys {
		_, _ = b.Write(ssh.MarshalAuthorizedKey(pubKey))
	}
	return b.Bytes()
}

func tv(s string) (ret bool, res string) {
	switch s {
	case CGIT: // ngrokSSH.exe -t
		res, _ = la(HUB4COM, RFC2217)
		return true, res
	case CGIV: // ngrokSSH.exe -v
		for _, exe := range []string{
			"winvnc.exe",
			"tvnserver.exe",
			"winvnc4.exe",
			"vncserver.exe",
			"repeater.exe",
		} {
			res, _ = la(exe, RFB)
			if res != "" {
				return true, res
			}
		}
		return true, res
	}
	return false, res
}
