/*
git clone https://github.com/abakum/ngrokSSH
go mod init github.com/abakum/ngrokSSH@latest
go get github.com/abakum/go-console@latest
go get github.com/abakum/winssh@latest
go get github.com/abakum/go-netstat@latest
go get github.com/abakum/proxy@latest

go get github.com/gliderlabs/ssh
go get github.com/pkg/sftp
go get golang.ngrok.com/ngrok@latest
go get github.com/ngrok/ngrok-api-go/v5
go get github.com/mitchellh/go-ps
go get github.com/blacknon/go-sshlib
go get github.com/Desuuuu/windrive
go get github.com/jimschubert/stripansi

go mod tidy
*/
package main

import (
	"bytes"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Desuuuu/windrive"
	"github.com/abakum/proxy"
	"github.com/abakum/winssh"
	"github.com/eiannone/keyboard"
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
	SSHD            = "sshd.exe"
	KITTY           = "kitty_portable.exe"
	REALVV          = "vncviewer.exe"
	CGIV            = "-v"
	CGIT            = "-t"
	CGIR            = "-r"
	MENU            = "Choose target for console - выбери цель подключения консоли"
	FiLEMODE        = 0644
	DIRMODE         = 0755
	KNOWN_HOSTS     = "known_hosts.ini"     //created on first run
	AUTHORIZED_KEYS = "authorized_keys.ini" //created on first run
	TOR             = time.Second * 15      //reconnect TO
	TOW             = time.Second * 5       //watch TO
	SOCKS5          = "1080"
	HTTPX           = "3128"
	B9600           = "9600"
	MARK            = '(' // '✅'
)

var (
	//go:embed NGROK_AUTHTOKEN.txt
	NgrokAuthToken string

	//go:embed NGROK_API_KEY.txt
	NgrokApiKey string

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
	KnownHosts,
	Crypt,
	RealVV,
	Cmd,
	_ string

	NgrokOnline,
	NgrokHasTunnel,
	A,
	D,
	N,
	O,
	h,
	X,
	a,
	r,
	t,
	v,
	n,
	dial,
	serv,
	PressEnter,
	_ bool

	L,
	R,
	V,
	T,
	C,
	Coms,
	_ arrayFlags

	Hub *exec.Cmd
	Fns map[string]string
	MenuToption,
	Ips []string
	MenuTid = 0
	Signer  gl.Signer
	KnownKeys,
	AuthorizedKeys []ssh.PublicKey
	Drives   []*windrive.Drive
	HardExe  = true // for linux symlink
	Once     sync.Once
	pemBytes []byte
	Bug      = "Ж"
	Gt       = ">"
	Delay    = DELAY
)

func main() {
	const (
		NGROK_AUTHTOKEN = "NGROK_AUTHTOKEN"
		NGROK_API_KEY   = "NGROK_API_KEY"
	)
	var (
		metadata,
		sp string
		err error
	)

	NgrokAuthToken = Getenv(NGROK_AUTHTOKEN, NgrokAuthToken) //create ngrok
	NgrokApiKey = Getenv(NGROK_API_KEY, NgrokApiKey)         //use ngrok

	Exe, err = os.Executable()
	a = isAnsi()
	Fatal(err)
	Image = filepath.Base(Exe)

	// CGI
	if len(os.Args) == 2 {
		ret, res := rtv(os.Args[1])
		if ret {
			if res == CGIR {
				listenaddress, sshdExe := la(SSHD, 22)
				if listenaddress != "" {
					sshd := strings.Split(sshdExe, ".")[0]
					restart := exec.Command("net.exe",
						"stop",
						sshd,
					)
					Println(cmd("Run", restart), restart.Run())
					time.Sleep(TOW + time.Second)
					restart = exec.Command("net.exe",
						"start",
						sshd,
					)
					Println(cmd("Run", restart), restart.Run())
				}
				Println(ngrokRestart(NgrokApiKey))
				return
			}
			fmt.Print(res)
			return
		}
	}

	Cwd, err = os.Getwd()
	Fatal(err)
	RealReset()

	RealVV = filepath.Join(Cwd, ROOT, REALVV)
	proxy.RealAddrBook(RealVV)

	Fns, _ = UnloadEmbedded(Bin, ROOT, Cwd, ROOT, true)

	pri := winssh.GetHostKey(Cwd)
	pemBytes, err = os.ReadFile(pri)
	if err != nil {
		Signer, err = winssh.GenerateSigner(pri)
	} else {
		Signer, err = ssh.ParsePrivateKey(pemBytes)
	}
	Fatal(err)

	pubKey := Signer.PublicKey()
	Println("HostKey", FingerprintSHA256(pubKey))
	rest := append([]byte("* "), ssh.MarshalAuthorizedKey(pubKey)...)

	KnownHosts = filepath.Join(Cwd, ROOT, KNOWN_HOSTS)
	_, err = os.Stat(KnownHosts)
	if os.IsNotExist(err) {
		Println("WriteFile", KnownHosts, os.WriteFile(KnownHosts, rest, FiLEMODE))
	}

	AuthorizedKeysIni = filepath.Join(Cwd, ROOT, AUTHORIZED_KEYS)
	for _, name := range winssh.GetUserKeysPaths(Cwd, AuthorizedKeysIni) {
		AuthorizedKeys = FileToAuthorized(name, AuthorizedKeys)
	}
	_, err = os.Stat(AuthorizedKeysIni)
	if os.IsNotExist(err) && len(AuthorizedKeys) > 0 {
		Println("WriteFile", AuthorizedKeysIni, os.WriteFile(AuthorizedKeysIni, MarshalAuthorizedKeys(AuthorizedKeys...), FiLEMODE))
	}

	rest, err = os.ReadFile(KnownHosts)
	if err != nil {
		Println(err)
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
				Println(FingerprintSHA256(pubKey))
				KnownKeys = append(KnownKeys, pubKey)
			}
		}
	}

	Coms, So, Cncb = GetDetailedPortsList()
	Cncb = `\\.\` + Cncb

	flag.BoolVar(&A, "A", false, fmt.Sprintf("authentication `agent` forwarding as - перенос авторизации как `ssh -A`\nexample - пример `%s -A`", Image))

	flag.Var(&C, "C", fmt.Sprintf("`COM` serial port for daemon - последовательный порт для сервера `hub4com`\nexample - пример `%s -C 7`", Image))
	flag.BoolVar(&D, "D", false, fmt.Sprintf("force LAN mode for `daemon` - режим локального сервера\nexample - пример `%s -D` or `%s @`", Image, Image))
	flag.Var(&L, "L", fmt.Sprintf("`local` port forwarding as - перенос ближнего порта как `ssh -L [bindHost:]bindPort[:dialHost:dialPort]` or\nlocal socks5 proxy as `ssh -D [bindHost:]bindPort`\nexample - пример `%s -L 80:0.0.0.0:80`", Image))
	flag.BoolVar(&N, "N", false, fmt.Sprintf("force `ngrok` mode - подключаться через туннель\nexample - пример `%s -N` or `%s :`", Image, Image))
	OpenSSH, err = exec.LookPath("ssh")
	if err == nil {
		flag.BoolVar(&O, "O", false, fmt.Sprintf("use ssh from `OpenSSH` - использовать `%s` вместо `%s`\nexample - пример `%s -O`", OpenSSH, Fns[KITTY], Image))
	} else {
		Println("OpenSSH", err)
	}

	flag.Var(&R, "R", fmt.Sprintf("`remote` port forwarding as - перенос дальнего порта как `ssh -R [bindHost:]bindPort:dialHost:dialPort` or\nremote socks5 proxy  as `ssh -R [bindHost:]bindPort`\nexample - пример `%s -R *:80::80`", Image))
	flag.StringVar(&S, "S", SOCKS5, fmt.Sprintf("port for proxy - порт для прокси `Socks5`\nexample - пример `%s -S 8080`", Image))
	flag.Var(&T, "T", fmt.Sprintf("local port forwarding for serial console over - перенос ближнего порта для последовательной консоли через `telnet` RFC2217 like -L\nexample - пример `%s -T 192.168.0.1:7000`", Image))
	flag.Var(&V, "V", fmt.Sprintf("local port forwarding for - перенос ближнего порта для `VNC` like -L\nexample - пример  `%s -V 5901`", Image))
	if runtime.GOOS == "windows" {
		flag.BoolVar(&X, "X", X, fmt.Sprintf("set by - устанавливать с помощью `setX` all_proxy\nexample - пример `%s -X`", Image))
		Drives, _ = windrive.List()
		HardExe = HardPath(Drives, Exe)
	}

	flag.BoolVar(&a, "a", a, fmt.Sprintf("`ansi` sequence enabled console - консоль поддерживает ansi последовательности\nexample - пример `%s -a` or `%s -a=false`", Image, Image))
	flag.StringVar(&Baud, "b", B9600, fmt.Sprintf("serial console `baud` - скорость последовательной консоли\nexample - пример `%s -b 115200` or `%s -b 1`", Image, Image))
	flag.BoolVar(&h, "h", h, fmt.Sprintf("show `help` for usage - показать использование параметров\nexample - пример `%s -h`", Image))
	flag.StringVar(&Ln, "l", "", fmt.Sprintf("`login` name as `ssh -l ln`\nexample - пример `%s -l root 192.168.0.1:2222` or `%s root@192.168.0.1:2222`", Image, Image))
	flag.BoolVar(&n, "n", false, fmt.Sprintf("do not use `ngrok` for dial - использовать режим LAN\nexample - пример `%s -n` or `%s .`", Image, Image))
	flag.StringVar(&sp, "p", PORT, fmt.Sprintf("ssh `port` as `ssh -p port ln@host` or `sshd -p port`\nexample - пример `%s -p 2222` or `%s -p 2222 root@192.168.0.1`", Image, Image))
	flag.BoolVar(&r, "r", false, fmt.Sprintf("`restart` daemon - перезапустить сервер\nexample - пример `%s -r`", Image))
	flag.StringVar(&So, "s", So, fmt.Sprintf("`serial` port for console - последовательный порт для консоли\nexample - пример `%s -s 11`", Image))
	flag.BoolVar(&t, "t", false, fmt.Sprintf("get binding of serial port over `telnet` daemon - где слушает сервер последовательного порта `hub4com`\nexample - пример `%s -t`", Image))
	flag.BoolVar(&v, "v", false, fmt.Sprintf("get binding of `VNC` daemon - где слушает сервер VNC\nexample - пример `%s -v`", Image))
	flag.Parse()
	SetPrefix(a)

	if h {
		fmt.Printf("Version %s of `%s params [user@][host[:port]] [command [params]]`\n", Ver, Image)
		flag.PrintDefaults()
		return
	}
	if actual(flag.CommandLine, "b") {
		i, err := strconv.Atoi(Baud)
		if err == nil {
			switch i {
			case 1:
				Baud = "115200"
			case 2:
				Baud = "2400"
			case 3:
				Baud = "38400"
			case 4:
				Baud = "4800"
			case 5:
				Baud = "57600"
			case 9:
				Baud = B9600
			}
		} else {
			Println(i, err)
			Baud = B9600
		}
	}
	if !actual(flag.CommandLine, "p") {
		_, err := strconv.Atoi(sp)
		if err != nil {
			sp = PORT
		}
	}
	if actual(flag.CommandLine, "V") {
		dial = true
	} else {
		V.Set("")
	}
	if actual(flag.CommandLine, "T") {
		dial = true
	} else {
		T.Set("")
	}

	if actual(flag.CommandLine, "C") {
		serv = true
	} else {
		C = Coms[:]
	}
	arg := flag.Arg(0)
	Hp = arg

	// PublicURL, metadata, err = ngrokGet(NgrokApiKey)
	// `ngrokSSH -D host:port` as `ngrokSSH @host:port`
	if strings.Contains(arg, "@") { // a@b:2222
		uhp := strings.Split(arg, "@") // [a b:2222]
		Ln = uhp[0]                    // a
		D = Ln == ""                   // @x
		if len(uhp) > 1 {              // b:2222
			Hp = uhp[1]
		}
	}

	// `ngrokSSH -N set` as `ngrokSSH : set` user from metadata and host:port from PublicURL
	// `ngrokSSH -n set` as `ngrokSSH . set` user and host:port from metadata
	if N || n {
		Cmd = strings.Join(flag.Args()[:], " ")
	} else if len(flag.Args()) > 1 {
		Cmd = strings.Join(flag.Args()[1:], " ")
	}
	switch Hp {
	case ":":
		N = true
	case ".":
		n = true
	}

	h, p := SplitHostPort(Hp, LH, sp)
	Hp = net.JoinHostPort(h, p)

	defer closer.Close()
	if Cmd == "" {
		closer.Bind(cleanup)
	}

	if psCount(Image, "", 0) != 1 {
		li.Println("Another one has been launched - Запущен ещё один", Image)
	}

	dial = dial || N || n || Ln != "" || Cmd != "" || A || O || X
	dial = dial || actual(flag.CommandLine, "L") || actual(flag.CommandLine, "R") || actual(flag.CommandLine, "S")
	serv = serv || D
	// for serial console need So!=""
	// `choco install com0com`
	if So != "" && !dial {
		items := []func(index int) string{}
		for _, opt := range T {
			hphp := parseHPHP(opt, RFC2217)
			p, err := strconv.Atoi(hphp[1])
			// is hub4com running local?
			if err == nil && isListen(hphp[0], p, 0) {
				//hub4com running local
				items = append(items, func(index int) string {
					if index > -1 {
						return fmt.Sprintf("%d) %s", index, strings.Join(hphp, ":"))
					}
					tty(hphp...)
					return ""
				})
			}
		}
		if len(items) > 0 {
			VisitAll("")
			li.Println("Local mode of serial console - Локальный режим последовательной консоли")
			menu(prompt, MARK, '1', len(items) == 1, true, items...)
		}
	}

	Ips = interfaces()
	FatalOr("not connected - нет сети", len(Ips) == 0)
	li.Println("Interfaces", Ips)

	if dial && !N && !n {
		if Println("Try connect by param - Подключаемся по параметрам", sshTry(un(""), h, p)) {
			client(un(""), h, p, p)
			return
		}
	}

	if D {
		// no need ngrok
	} else {
		PublicURL, metadata, err = ngrokGet(NgrokApiKey)
		Println(PublicURL, metadata, err)
		NgrokHasTunnel = err == nil
		NgrokOnline = NgrokHasTunnel || errors.Is(err, ErrNgrokOnlineNoTunnel)
	}
	// serv := !dial && (arg != "" || actual(flag.CommandLine, "p"))
	// ngrokSSH `*` as `0.0.0.0:22`
	// ngrokSSH `*:2222` as `0.0.0.0:2222`
	// ngrokSSH `-p 2222` as `127.0.0.1:2222`
	// ngrokSSH `:2222` as `127.0.0.1:2222`
	// `ngrokSSH @x` as `ngrokSSH -n x`

	if NgrokHasTunnel && !serv {
		client(fromNgrok(PublicURL, metadata))
		return
	}

	for {
		server()
		winssh.KidsDone(os.Getpid())
		time.Sleep(TOR)
	}
}

func prompt(index int, d rune) string {
	return MENU
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
	return fmt.Sprintf(`%s>%s %s`, s, quote(c.Args[0]), strings.Join(c.Args[1:], " "))
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
			Println(name, FingerprintSHA256(out))
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

func rtv(s string) (ret bool, res string) {
	switch s {
	case CGIR: // ngrokSSH.exe -r
		return true, CGIR
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

func HardPath(Drives []*windrive.Drive, path string) (hard bool) {
	if len(Drives) < 1 || !(len(path) > 1 && path[1] == ':') {
		return true //for linux
	}
	for _, drive := range Drives {
		for _, partition := range drive.Partitions {
			if !partition.Removable && strings.HasPrefix(strings.ToUpper(path), partition.Path) {
				return true
			}
		}
	}
	return
}

func RealReset() {
	ProxyType, ProxyServer := proxy.RealGet()
	if ProxyServer != "" {
		// after panic?
		if ProxyType == "" {
			ProxyType = "socks"
		}
		Println("RealGet", ProxyType, ProxyServer)
		h, p := SplitHostPort(ProxyServer, LH, SOCKS5)
		if ProxyType != "socks" {
			h, p = SplitHostPort(ProxyServer, LH, HTTPX)
		}
		x, err := strconv.Atoi(p)
		if err == nil && isListen(h, x, 0) {
			if X {
				if ProxyType == "socks" {
					setX("all_proxy", ProxyType+"://"+net.JoinHostPort(h, p))
				} else {
					setX(ProxyType+"_proxy", ProxyType+"://"+net.JoinHostPort(h, p))
				}
			}
			ProxyServer = net.JoinHostPort(h, p)
			proxy.RealSet(ProxyType, ProxyServer)
			Println("RealSet", ProxyType, ProxyServer)
			return
		}
		proxy.RealSet("", "")
		Println("RealSet", "", "")
		return
	}
}

type BasicUI struct {
	Reader      io.Reader
	Writer      io.Writer
	ErrorWriter io.Writer
}

func menu(prompt func(index int, def rune) string, mark, def rune, keyEnter, exitOnTypo bool, items ...func(index int) string) {
	const runFunc = -1
	var (
		key   keyboard.Key
		err   error
		r     rune
		index = -1
	)
	for {
		// Print menu
		fmt.Println()
		newD := false // search mark or set GT by index
		for i, item := range items {
			rs := []rune(item(i)) //get menu item
			if len(rs) < 1 {
				continue
			}
			newD = rs[0] == mark
			if newD {
				if len(rs) < 2 {
					continue
				}
				rs = rs[1:]
			}
			if index > -1 {
				if index == i {
					def = rs[0]
				}
			} else {
				if newD {
					def = rs[0]
				}
			}
		}

		index = -1
		for i, item := range items { //print menu
			rs := []rune(item(i)) //get menu item
			if len(rs) < 1 {
				continue
			}
			m := " "
			if rs[0] == mark { // new d
				if len(rs) < 2 {
					continue
				}
				m = string(mark)
				rs = rs[1:]
			}
			if def == rs[0] {
				m = Gt
				index = i
			}
			fmt.Printf("%s%s\n", m, string(rs))
		}
		fmt.Print(prompt(index, def), Gt)
		if keyEnter {
			r = def
		} else {
			r, key, err = keyboard.GetSingleKey()
			if err != nil {
				fmt.Println(Bug)
				return
			}
			if key == keyboard.KeyEnter {
				r = def
			}
		}
		keyEnter = false
		def = r
		if r == 0 {
			fmt.Printf("0x%X\n", key)
			switch key {
			case keyboard.KeyHome:
				index = 0
				continue
			case keyboard.KeyArrowUp:
				if index == 0 {
					index = len(items) - 1
				} else {
					index--
				}
				continue
			case keyboard.KeyEnd:
				index = len(items) - 1
				continue
			case keyboard.KeyArrowDown:
				if index == len(items)-1 {
					index = 0
				} else {
					index++
				}
				continue
			}
		} else {
			fmt.Printf("%c\n", def)
		}
		index = -1
		ok := false
	doit:
		for i, item := range items {
			rs := []rune(item(i)) //get menu item
			if len(rs) < 1 {
				continue
			}
			if rs[0] == mark { //ignore mark from item
				if len(rs) < 2 {
					continue
				}
				rs = rs[1:]
			}
			ok = def == rs[0]
			if ok {
				if len(item(runFunc)) > 0 { // run func of menu item
					return // for once selected menu
				}
				break doit
			}
		}
		if exitOnTypo && !ok {
			return
		}
	}
}
