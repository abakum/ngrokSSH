package main

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

go get internal/tool
go get github.com/abakum/embed-encrypt
go get download github.com/abakum/version
go mod tidy
*/

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
	"time"

	"github.com/abakum/embed-encrypt/encryptedfs"
	"github.com/abakum/menu"
	"github.com/abakum/proxy"

	version "github.com/abakum/version/lib"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"github.com/mitchellh/go-ps"
	"github.com/xlab/closer"
	"go.bug.st/serial"
	"go.bug.st/serial/enumerator"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows/registry"
)

var _ = version.Ver

//go:generate go run github.com/abakum/version
//go:generate go run bin/main.go
//go:generate go run github.com/abakum/embed-encrypt
// go:generate go list -f '{{.EmbedFiles}}'

const (
	PORT     = "22"
	ALL      = "0.0.0.0"
	LH       = "127.0.0.1"
	RFC2217  = 2217
	RFB      = 5900
	EMULATOR = "com0com - serial port emulator"
	COM0COM  = "https://sourceforge.net/projects/com0com/files/com0com/3.0.0.0/com0com-3.0.0.0-i386-and-x64-signed.zip/download" // signed
	ROOT     = "bin"
	LIMIT    = "1"
	ITO      = "10"
	XO       = "on"
	DELAY    = "0.05"
	HUB4COM  = "hub4com.exe" // unSigned https://sourceforge.net/projects/com0com/files/hub4com/
	// XTTY            = "kitty_portable.exe" // unSigned https://github.com/cyd01/KiTTY
	XTTY     = "putty.exe"     // signed https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
	REALVV   = "vncviewer.exe" // signed http://www.oldversion.com/windows/realvnc-5-0-4
	SSHD     = "sshd.exe"      // signed https://github.com/PowerShell/Win32-OpenSSH/releases
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
	Spaces   = " \t\n\v\f\r\u0085\u00A0"
)

//encrypted:embed NGROK_AUTHTOKEN.txt
var NgrokAuthToken string

//encrypted:embed NGROK_API_KEY.txt
var NgrokApiKey string

//encrypted:embed bin/randomseed
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
	n,
	dial,
	serv,
	PressEnter,
	IsOSSH,
	AuthByCert,
	KnownHostByCert,
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
	Delay       = DELAY
	CertCheck   *ssh.CertChecker
	AuthMethods []ssh.AuthMethod
	Signers,
	CertSigners,
	AgentSigners []ssh.Signer
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
	NgrokAuthToken = Getenv(NGROK_AUTHTOKEN, NgrokAuthToken) //create ngrok tunnel
	NgrokApiKey = Getenv(NGROK_API_KEY, NgrokApiKey)         //use ngrok

	Exe, err = os.Executable()
	Fatal(err)
	Image = filepath.Base(Exe)
	Imag = strings.Split(Image, ".")[0]

	// CGI
	if len(os.Args) == 2 {
		if os.Args[1] == CGIR {
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
	}

	// Cwd, err = os.Getwd()
	Cwd, err = os.UserHomeDir()

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
	Signers, UserKnownHostsFile = getSigners(Signer, Imag, Imag)
	AuthMethods = append(AuthMethods, ssh.PublicKeys(Signers...))
	CertSigners = []ssh.Signer{}
	AgentSigners = []ssh.Signer{}
	for i, signer := range Signers {
		_, ok := signer.PublicKey().(*ssh.Certificate)
		if ok || i == 0 {
			CertSigners = append(CertSigners, signer)
		} else {
			AgentSigners = append(AgentSigners, signer)
		}
	}

	// for client
	// knownKeys := getKnownKeys()

	// HostKeyFallback, err := knownhosts.New(filepath.Join(UserHomeDirs(".ssh"), "known_hosts"))
	// if err != nil {
	// 	Println(err)
	// }
	CertCheck = &ssh.CertChecker{
		IsHostAuthority: func(p ssh.PublicKey, addr string) bool {
			return gl.KeysEqual(p, Signer.PublicKey())
		},
		// HostKeyFallback: HostKeyCallback(knownKeys...),
		// HostKeyFallback: HostKeyFallback,
		HostKeyFallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			// Println(hostname, remote, FingerprintSHA256(key))
			KnownHostByCert = false
			return nil // InsecureIgnoreHostKey for trySSH
		},
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
		// Drives, _ = windrive.List()
		// HardExe = HardPath(Drives, Exe)
	}
	a = menu.IsAnsi()
	flag.BoolVar(&a, "a", a, fmt.Sprintf("`ansi` sequence enabled console - консоль поддерживает ansi последовательности\nexample - пример `%s -a` or `%s -a=false`", Image, Image))
	flag.StringVar(&Baud, "b", B9600, fmt.Sprintf("serial console `baud` - скорость последовательной консоли\nexample - пример `%s -b 115200` or `%s -b 1`", Image, Image))
	flag.BoolVar(&h, "h", h, fmt.Sprintf("show `help` for usage - показать использование параметров\nexample - пример `%s -h`", Image))
	flag.StringVar(&Ln, "l", "", fmt.Sprintf("`login` name as `ssh -l ln`\nexample - пример `%s -l root 192.168.0.1:2222` or `%s root@192.168.0.1:2222` or `%s _@` where `_` as %%USERNAME%%", Image, Image, Image))
	flag.BoolVar(&n, "n", false, fmt.Sprintf("do not use `ngrok` for dial - использовать режим LAN\nexample - пример `%s -n` or `%s .`", Image, Image))
	flag.StringVar(&sp, "p", PORT, fmt.Sprintf("ssh `port` as `ssh -p port ln@host` or `sshd -p port`\nexample - пример `%s -p 2222` or `%s -p 2222 root@192.168.0.1`", Image, Image))
	flag.BoolVar(&r, "r", false, fmt.Sprintf("`restart` daemon - перезапустить сервер\nexample - пример `%s -r`", Image))
	flag.StringVar(&So, "s", So, fmt.Sprintf("`serial` port for console - последовательный порт для консоли\nexample - пример `%s -s 11`", Image))
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

type hostKeys struct {
	keys []ssh.PublicKey
}

func (f *hostKeys) check(hostname string, remote net.Addr, key ssh.PublicKey) error {
	Println(hostname, remote, FingerprintSHA256(key))
	if len(f.keys) == 0 {
		return fmt.Errorf("ssh: no required host keys")
	}
	for _, fKey := range f.keys {
		if gl.KeysEqual(key, fKey) {
			return nil
		}
		// Println(FingerprintSHA256(fKey))
	}
	return fmt.Errorf("ssh: no one host key from %d match %s", len(f.keys), FingerprintSHA256(key))
}

// HostKeyCallback returns a function for use in
// ClientConfig.HostKeyCallback to accept specific host keys.
func HostKeyCallback(keys ...ssh.PublicKey) ssh.HostKeyCallback {
	hk := &hostKeys{keys}
	return hk.check
}

// Возвращаем сигнеров от агента, и сертификаты от агента и самоподписанный сертификат ЦС.
// Пишем ветку реестра SshHostCAs для putty клиента и файл UserKnownHostsFile для ssh клиента чтоб они доверяли хосту по сертификату от ЦС caSigner.
// Если новый ключ ЦС (.ssh/ca.pub) или новый ключ от агента пишем сертификат в файл для ssh клиента и ссылку на него в реестр для putty клиента чтоб хост с ngrokSSH им доверял.
// Если новый ключ ЦС пишем конфиги и сертифкаты для sshd от OpenSSH чтоб sshd доверял клиентам ngrokSSH, putty, ssh.
func getSigners(caSigner ssh.Signer, id string, user string) (signers []ssh.Signer, userKnownHostsFile string) {
	// разрешения для сертификата пользователя
	var permits = make(map[string]string)
	for _, permit := range []string{
		"X11-forwarding",
		"agent-forwarding",
		"port-forwarding",
		"pty",
		"user-rc",
	} {
		permits["permit-"+permit] = ""
	}

	ss := []ssh.Signer{caSigner}
	// agent
	rw, err := NewConn()
	if err == nil {
		defer rw.Close()
		ea := agent.NewClient(rw)
		eas, err := ea.Signers()
		if err == nil {
			ss = append(ss, eas...)
		}
	}
	// в ss ключ ЦС caSigner и ключи от агента
	if len(ss) < 2 {
		Println(fmt.Errorf("no keys from agent - не получены ключи от агента %v", err))
	}
	sshUserDir := UserHomeDirs(".ssh")
	userKnownHostsFile = filepath.Join(sshUserDir, "known_ca")
	newCA := false
	for i, idSigner := range ss {
		signers = append(signers, idSigner)

		pub := idSigner.PublicKey()

		pref := "ca"
		if i > 0 {
			t := strings.TrimPrefix(pub.Type(), "ssh-")
			if strings.HasPrefix(t, "ecdsa") {
				t = "ecdsa"
			}
			pref = "id_" + t
		}

		data := ssh.MarshalAuthorizedKey(pub)
		name := filepath.Join(sshUserDir, pref+".pub")
		old, err := os.ReadFile(name)
		newPub := err != nil || !bytes.Equal(data, old)
		if i == 0 {
			newCA = newPub
			if newCA {
				certHost(caSigner, Imag)
			}
		}
		if newPub {
			Println(name, os.WriteFile(name, data, FILEMODE))
			if i == 0 { // ca.pub know_ca idSigner is caSigner
				bb := bytes.NewBufferString("@cert-authority * ")
				bb.Write(data)
				// пишем файл UserKnownHostsFile для ssh клиента чтоб он доверял хосту по сертификату ЦС caSigner
				Println(userKnownHostsFile, os.WriteFile(userKnownHostsFile, bb.Bytes(), FILEMODE))
				// for putty ...they_verify_me_by_certificate
				// пишем ветку реестра SshHostCAs для putty клиента чтоб он доверял хосту по сертификату ЦС caSigner
				rk, _, err := registry.CreateKey(registry.CURRENT_USER,
					`SOFTWARE\SimonTatham\PuTTY\SshHostCAs\`+Imag,
					registry.CREATE_SUB_KEY|registry.SET_VALUE)
				if err == nil {
					rk.SetStringValue("PublicKey", strings.TrimSpace(strings.TrimPrefix(string(data), pub.Type())))
					rk.SetStringValue("Validity", "*")
					rk.SetDWordValue("PermitRSASHA1", 0)
					rk.SetDWordValue("PermitRSASHA256", 1)
					rk.SetDWordValue("PermitRSASHA512", 1)
					rk.Close()
				} else {
					Println(err)
				}
			}
		}
		mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner),
			[]string{caSigner.PublicKey().Type()})
		if err != nil {
			continue
		}
		//ssh-keygen -s ca -I id -n user -V always:forever ~\.ssh\id_*.pub
		certificate := ssh.Certificate{
			Key:             idSigner.PublicKey(),
			CertType:        ssh.UserCert,
			KeyId:           id,
			ValidBefore:     ssh.CertTimeInfinity,
			ValidPrincipals: []string{user},
			Permissions:     ssh.Permissions{Extensions: permits},
		}
		if certificate.SignCert(rand.Reader, mas) != nil {
			continue
		}

		certSigner, err := ssh.NewCertSigner(&certificate, idSigner)
		if err != nil {
			continue
		}
		// добавляем сертификат в слайс результата signers
		signers = append(signers, certSigner)

		if newCA || newPub {
			//если новый ключ ЦС или новый ключ от агента пишем сертификат в файл для ssh клиента и ссылку на него в реестр для putty клиента
			name = filepath.Join(sshUserDir, pref+"-cert.pub")
			err = os.WriteFile(name,
				ssh.MarshalAuthorizedKey(&certificate),
				FILEMODE)
			Println(name, err)
			if i == 1 {
				// пишем ссылку на один сертификат (первый) в ветку реестра ngrokSSH для putty клиента
				if err == nil {
					// for I_verify_them_by_certificate_they_verify_me_by_certificate
					// PuTTY -load ngrokSSH user@host
					forPutty(`SOFTWARE\SimonTatham\PuTTY\Sessions\`+Imag, name)
				}
				// PuTTY user@host
				forPutty(`SOFTWARE\SimonTatham\PuTTY\Sessions\Default%20Settings`, "")
			}
		}
	}
	return
}

// Если установлен sshd от OpenSSH обновляем TrustedUserCAKeys (ssh/trusted_user_ca_keys) и HostCertificate.
// Пишем конфиг I_verify_them_by_key_they_verify_me_by_certificate.
// Пишем конфиг I_verify_them_by_certificate_they_verify_me_by_certificate.
// Предлагаем включить один из этих конфигов в __PROGRAMDATA__/ssh/sshd_config.
func certHost(caSigner ssh.Signer, id string) (err error) {
	// ssh-keygen -s ca -I ngrokSSH -h -V always:forever c:\ProgramData\ssh\ssh_host_ecdsa_key.pub
	// move c:\ProgramData\ssh\ssh_host_ecdsa_key-cert.pub c:\ProgramData\ssh\host_certificate
	sshHostKey := GetHostKey("")
	if sshHostKey == "" {
		return fmt.Errorf("not found OpenSSH keys")
	}
	//type ca.pub>>c:\ProgramData\ssh\trusted_user_ca_keys
	sshHostDir := filepath.Dir(sshHostKey)
	TrustedUserCAKeys := filepath.Join(sshHostDir, "trusted_user_ca_keys")
	ca := caSigner.PublicKey()
	data := ssh.MarshalAuthorizedKey(ca)
	old, err := os.ReadFile(TrustedUserCAKeys)
	newCA := err != nil || !bytes.Equal(data, old)
	if newCA {
		Println(TrustedUserCAKeys, os.WriteFile(TrustedUserCAKeys, data, FILEMODE))
	}

	sshHostKeyPub := sshHostKey + ".pub"
	pub, err := os.Stat(sshHostKeyPub)
	if err != nil {
		return
	}
	in, err := os.ReadFile(sshHostKeyPub)
	if err != nil {
		return
	}
	out, _, _, _, err := ssh.ParseAuthorizedKey(in)
	if err != nil {
		out, err = ssh.ParsePublicKey(in)
	}
	if err != nil {
		return
	}
	HostCertificate := filepath.Join(sshHostDir, "host_certificate")
	cert, err := os.Stat(HostCertificate)
	newPub := true
	if err == nil {
		newPub = cert.ModTime().Unix() < pub.ModTime().Unix()
	}
	if !(newCA || newPub) {
		return nil
	}

	//newCA || newPub
	mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner), []string{ca.Type()})
	if err != nil {
		return
	}
	certificate := ssh.Certificate{
		Key:         out,
		CertType:    ssh.HostCert,
		KeyId:       id,
		ValidBefore: ssh.CertTimeInfinity,
		// ValidAfter:  uint64(time.Now().Unix()),
		// ValidBefore: uint64(time.Now().AddDate(1, 0, 0).Unix()),
	}
	err = certificate.SignCert(rand.Reader, mas)
	if err != nil {
		return
	}
	data = ssh.MarshalAuthorizedKey(&certificate)
	err = os.WriteFile(HostCertificate, data, FILEMODE)
	Println(HostCertificate, err)
	if err != nil {
		return
	}

	include := filepath.Join(sshHostDir, "I_verify_them_by_key_they_verify_me_by_certificate")
	s := `HostCertificate __PROGRAMDATA__/ssh/host_certificate
Match Group administrators
AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys
`
	err = os.WriteFile(include, []byte(s), FILEMODE)
	Println(include, err)
	if err != nil {
		return
	}
	Println("Insert to __PROGRAMDATA__/ssh/sshd_config line `Include I_verify_them_by_key_they_verify_me_by_certificate`.")

	include = filepath.Join(sshHostDir, "authorized_principals")
	err = os.WriteFile(include, []byte(id), FILEMODE)
	Println(include, err)
	if err != nil {
		return
	}

	include = filepath.Join(sshHostDir, "I_verify_them_by_certificate_they_verify_me_by_certificate")
	s = `TrustedUserCAKeys __PROGRAMDATA__/ssh/trusted_user_ca_keys
AuthorizedPrincipalsFile __PROGRAMDATA__/ssh/authorized_principals
HostCertificate __PROGRAMDATA__/ssh/host_certificate
`
	err = os.WriteFile(include, []byte(s), FILEMODE)
	Println(include, err)
	Println("Or insert to __PROGRAMDATA__/ssh/sshd_config line `I_verify_them_by_certificate_they_verify_me_by_certificate`.")
	return
}
