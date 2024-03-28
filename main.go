/*
git clone https://github.com/abakum/ngrokSSH
go mod init github.com/abakum/ngrokSSH
go get github.com/abakum/go-console@latest
go get github.com/abakum/winssh@latest
go get github.com/abakum/go-netstat@latest
go get github.com/abakum/proxy@latest
go get github.com/abakum/menu@latest
go get github.com/abakum/go-ansiterm@latest
go get github.com/abakum/go-sshlib@latest

go get github.com/gliderlabs/ssh
go get github.com/pkg/sftp
go get golang.ngrok.com/ngrok@v1.7.0
go get github.com/ngrok/ngrok-api-go/v5
go get github.com/mitchellh/go-ps
go get github.com/Desuuuu/windrive

go get internal/tool
go get github.com/abakum/embed-encrypt
go mod tidy
*/
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
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
	"github.com/abakum/embed-encrypt/encryptedfs"
	"github.com/abakum/menu"
	"github.com/abakum/proxy"
	_ "github.com/abakum/version"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"github.com/mitchellh/go-ps"
	"github.com/xlab/closer"
	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
	"golang.org/x/crypto/ssh"
)

//go:generate go run github.com/abakum/version
//go:generate go run bin/main.go
//go:generate go run github.com/abakum/embed-encrypt

const (
	PORT     = "22"
	ALL      = "0.0.0.0"
	LH       = "127.0.0.1"
	RFC2217  = 2217
	RFB      = 5900
	EMULATOR = "com0com - serial port emulator"
	COM0COM  = "https://sourceforge.net/projects/com0com/files/com0com/3.0.0.0/com0com-3.0.0.0-i386-and-x64-signed.zip/download"
	ROOT     = "bin"
	LIMIT    = "1"
	ITO      = "10"
	XO       = "on"
	DELAY    = "0.05"
	HUB4COM  = "hub4com.exe"
	SSHD     = "sshd.exe"
	// XTTY            = "kitty_portable.exe"
	XTTY     = "putty.exe"
	REALVV   = "vncviewer.exe"
	CGIV     = "-v"
	CGIT     = "-t"
	CGIR     = "-r"
	MENU     = "Choose target for console - выбери цель подключения консоли"
	FILEMODE = 0644
	DIRMODE  = 0755
	TOR      = time.Second * 15 //reconnect TO
	TOW      = time.Second * 5  //watch TO
	SOCKS5   = "1080"
	HTTPX    = "3128"
	B9600    = "9600"
	MARK     = '('
	SSH2     = "SSH-2.0-"
	OSSH     = "OpenSSH_for_Windows"
	KiTTY    = "KiTTY"
)

//encrypted:embed NGROK_AUTHTOKEN.txt
var NgrokAuthToken string

//encrypted:embed NGROK_API_KEY.txt
var NgrokApiKey string

//encrypted:embed bin/kitty.rnd
var CA []byte

//encrypted:embed bin/*.exe bin/Sessions/Default%20Settings bin/AB/*
var Bin encryptedfs.FS

//go:embed VERSION
var Ver string

var (
	Hp,
	Cwd,
	Exe,
	Image,
	Imag,
	PublicURL,
	Ln,
	So,
	Cncb,
	Rfc2217,
	Vnc,
	Baud,
	S,
	OpenSSH,
	Crypt,
	RealVV,
	Cmd,
	UserKnownHostsFile,
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
	IsOSSH,
	IsCert,
	_ bool
	IsKiTTY = strings.Contains(XTTY, strings.ToLower(KiTTY))

	L,
	R,
	V,
	T,
	C,
	Coms,
	_ arrayFlags

	Hub    *exec.Cmd
	Fns    map[string]string
	report string
	MenuToption,
	Ips []string
	MenuTid = 0
	Signer  gl.Signer //ca
	KnownKeys,
	AuthorizedKeys []ssh.PublicKey
	Drives      []*windrive.Drive
	HardExe     = true // for linux symlink
	Once        sync.Once
	Delay       = DELAY
	CertCheck   *ssh.CertChecker
	AuthMethods []ssh.AuthMethod
	Signers     []ssh.Signer
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
	Fatal(err)
	Image = filepath.Base(Exe)
	Imag = strings.Split(Image, ".")[0]

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

	Ips = interfaces()
	Println(runtime.GOOS, runtime.GOARCH, Imag, Ver, Ips)
	FatalOr("not connected - нет сети", len(Ips) == 0)

	Fns, report, err = encryptedfs.Xcopy(Bin, ROOT, Cwd, "")
	if report != "" {
		Println(report)
	}
	Fatal(err)

	key, err := x509.ParsePKCS8PrivateKey(CA)
	Fatal(err)
	Signer, err = ssh.NewSignerFromKey(key)
	Fatal(err)

	AuthorizedKeys = append(AuthorizedKeys, Signer.PublicKey())
	Signers = getSigners(Signer, Imag, Imag)
	AuthMethods = append(AuthMethods, ssh.PublicKeys(Signers...))

	CertCheck = &ssh.CertChecker{
		IsHostAuthority: func(p ssh.PublicKey, addr string) bool {
			return gl.KeysEqual(p, Signer.PublicKey())
		},
		// HostKeyFallback: sshlib.HostKeyCallback(KnownKeys...),
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
		flag.BoolVar(&O, "O", false, fmt.Sprintf("use ssh from `OpenSSH` - использовать `%s` вместо `%s`\nexample - пример `%s -O`", OpenSSH, Fns[XTTY], Image))
	} else {
		Println(OSSH, err)
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
	a = menu.IsAnsi()
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

	if h {
		fmt.Printf("Version %s of `%s params [user@][host[:port]] [command [params]]`\n", Ver, Image)
		flag.PrintDefaults()
		return
	}

	SetColor()

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
	if So != "" && !dial {
		// items := []func(index int) string{}
		items := []menu.MenuFunc{menu.Static(MENU).Prompt}
		for _, opt := range T {
			hphp := parseHPHP(opt, RFC2217)
			p, err := strconv.Atoi(hphp[1])
			// is hub4com running local?
			if err == nil && isListen(hphp[0], p, 0) {
				//hub4com running local
				items = append(items, func(index int, pressed rune) string {
					return ttyMenu(index, pressed, hphp...)
				})
			}
		}
		if len(items) > 1 {
			VisitAll("")
			li.Println("Local mode of serial console - Локальный режим последовательной консоли")
			menu.Menu('1', len(items) == 2, true, items...)
		}
	}

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
	menu.PressAnyKey("Press any key - Нажмите любую клавишу", TOW)
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

// like gl.GenerateSigner plus write key to files
func GenerateSigner(pri string) (gl.Signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err == nil {
		data := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: Bytes,
		})
		if data != nil {
			os.WriteFile(pri, data, FILEMODE)
		}

		Bytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
		if err == nil {
			data := pem.EncodeToMemory(&pem.Block{
				Type:  "PUBLIC KEY",
				Bytes: Bytes,
			})

			os.WriteFile(pri+".pub", data, FILEMODE)
		}
	}

	return ssh.NewSignerFromKey(key)
}

// get one key
func GetHostKey(ssh string) (pri string) {
	for _, dir := range []string{
		filepath.Join(os.Getenv("ALLUSERSPROFILE"), "ssh"),
		ssh,
	} {
		for _, key := range []string{
			"ssh_host_ecdsa_key",
			"ssh_host_ed25519_key",
			"ssh_host_rsa_key",
		} {
			pri = filepath.Join(dir, key)
			ltf.Println(pri)
			_, err := os.Stat(pri)
			if err == nil {
				return
			}
		}
	}
	return
}

func FingerprintSHA256(pubKey ssh.PublicKey) string {
	return pubKey.Type() + " " + ssh.FingerprintSHA256(pubKey)
}
