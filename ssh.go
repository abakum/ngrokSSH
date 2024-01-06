package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	_ "embed"

	"github.com/Microsoft/go-winio"
	"github.com/abakum/pageant"
	"github.com/abakum/proxy"
	"github.com/blacknon/go-sshlib"
	"github.com/dixonwille/wmenu/v5"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows/registry"
)

const (
	USER    = 1024
	REALVAB = "vncaddrbook.exe"
)

var (
	// go:embed authorized_keys
	Authorized_keys []byte
)

func client(user, host, port, listenAddress string) {
	const (
		GEOMETRY = "-geometry=300x600+0+0"
		AB       = "AB"
	)
	var (
		sock        net.Conn
		signers     []ssh.Signer
		session     *ssh.Session
		menuVoption []string
		menuVid     = 0
	)
	title := fmt.Sprintf("%s@%s:%s", user, host, port)

	VisitAll(title)

	sock, Err = NewConn()
	if Err != nil {
		Err = srcError(Err)
		return
	}
	defer sock.Close()

	var b bytes.Buffer
	con := &sshlib.Connect{
		ForwardAgent: A,
		Agent:        agent.NewClient(sock),
		Stdout:       &b,
	}

	signers, Err = sshlib.CreateSignerAgent(con.Agent)
	if Err != nil || len(signers) == 0 {
		Err = srcError(Err)
		return
	}

	Err = con.CreateClient(host, port, user, []ssh.AuthMethod{ssh.PublicKeys(signers...)})
	if Err != nil {
		Err = srcError(Err)
		return
	}

	// Create Session
	session, Err = con.CreateSession()
	if Err != nil {
		Err = srcError(Err)
		return
	}

	for _, o := range V {
		hphp, e := cgi(con, Image+" "+CGIV, o, RFB, &b)
		if e != nil {
			continue
		}
		menuVoption = append(menuVoption, strings.Join(hphp, ":"))
	}

	if actual(flag.CommandLine, "S") || len(menuVoption) > 0 {
		i5, er := strconv.Atoi(S)
		if er == nil && !isListen("", i5, 0) {
			L = append(L, S)
			// gosysproxy.SetGlobalProxy("socks=" + net.JoinHostPort(LH, S))
			// setX("all_proxy", "socks://"+net.JoinHostPort(LH, S))
			proxy.RealSet("socks", net.JoinHostPort(LH, S))
			closer.Bind(func() {
				// gosysproxy.Off()
				// setX("all_proxy", "")
				proxy.RealSet("", "")
			})
		}
	}

	for _, o := range L {
		tryBindL(con, parseHPHP(o, USER)...)
	}

	for _, o := range R {
		tryBindR(con, parseHPHP(o, USER)...)
	}

	if So == "" {
		letf.Printf("not found %s\n`setupc install 0 PortName=COM#,RealPortName=COM11,EmuBR=yes,AddRTTO=1,AddRITO=1 -`\n", EMULATOR)
	} else {
		for _, o := range T {
			hphp, e := cgi(con, Image+" "+CGIT, o, RFC2217, &b)
			if e != nil {
				continue
			}
			MenuToption = append(MenuToption, strings.Join(hphp, ":"))
		}
	}

	ska(con, session, false)
	switch {
	case actual(flag.CommandLine, "T"):
		menuVid = len(menuVoption) + 1
		if len(MenuToption) == 1 {
			tty(parseHPHP(MenuToption[0], RFC2217)...)
		}
	case actual(flag.CommandLine, "V"):
		menuVid = 1
		opts := []string{GEOMETRY}
		if psCount(REALVAB, "", 0) == 0 {
			opts = append(opts,
				"-ViewerPath="+Exe,
				"-MinimiseToTray=0",
				"-AddressBook="+Fns[AB],
			)
		}
		vab := exec.Command(Fns[REALVAB], opts...)
		PrintOk(cmd("Start", vab), vab.Start())
		if len(menuVoption) == 1 {
			mV(menuVoption[0])
		}
	default:
		mO(title, user, host, port)
	}
	for {
		menuV := wmenu.NewMenu(MENU)
		menuV.Action(func(opts []wmenu.Opt) error {
			for _, opt := range opts {
				menuVid = opt.ID
				switch {
				case menuVid == 0:
					mO(title, user, host, port)
					return nil
				case menuVid > len(menuVoption):
					tty(parseHPHP(opt.Text, RFC2217)...)
					return nil
				default:
					mV(opt.Text)
					return nil
				}
			}
			return nil
		})
		menuV.Option(title, nil, menuVid == 0, nil)
		for i, opt := range append(menuVoption, MenuToption...) {
			menuV.Option(opt, nil, menuVid == i+1, nil)
		}
		if menuV.Run() != nil {
			return
		}
	}
}

func mV(opt string) {
	vvO := []string{
		"-ChangeServerDefaultPrinter=0",
		"-EnableChat=0",
		"-Scaling=None",
		"-SecurityNotificationTimeout=0",
		"-ShareFiles=0",
		"-UserName=",
		"-VerifyId=0",
		"-WarnUnencrypted=0",
		"-SingleSignOn=0",
		"-ProxyServer=",
	}
	hphp := parseHPHP(opt, RFB)
	vv := exec.Command(Fns[REALVV], append(vvO, net.JoinHostPort(hphp[0], hphp[1]))...)
	PrintOk(cmd("Start", vv), vv.Start())
}

func mO(title, user, host, port string) {
	opts := []string{
		title,
		"-title",
		title,
	}
	for _, key := range KnownKeys {
		opts = append(opts,
			"-hostkey",
			ssh.FingerprintSHA256(key),
		)
	}

	sshExe := Fns[KITTY]
	if O {
		sshExe = OpenSSH
		opts = []string{
			"-l",
			user,
			host,
			"-p",
			port,
			"-o",
			fmt.Sprintf("UserKnownHostsFile=%s", Fns[KNOWN_HOSTS]),
		}
	}
	if A {
		opts = append(opts, "-A")
	}
	ki := exec.Command(sshExe, opts...)
	if O {
		ki.Stdout = os.Stdout
		ki.Stderr = os.Stdout
		ki.Stdin = os.Stdin
		li.Println(cmd("Run", ki))
		ki.Run()
	} else {
		PrintOk(cmd("Start", ki), ki.Start())
	}
}

func fromNgrok(publicURL, meta string) (user, host, port, listenAddress string) {
	unp := strings.Split(meta, "@")
	u := un(unp[0])
	p := PORT
	if !N {
		np := net.JoinHostPort(ALL, PORT)
		if len(unp) > 1 {
			np = unp[1]
		}
		netsPort := strings.Split(np, ":")
		if len(netsPort) > 1 {
			p = netsPort[1]
		}
		nets := strings.Split(netsPort[0], ",")
		for _, ip := range nets {
			if listenAddress == "" {
				listenAddress = net.JoinHostPort(ip, p)
			}
			ltf.Println("try local")
			if sshTry(u, ip, p) == nil {
				user, host, port = u, ip, p
				return
			}
		}
	}
	tcp, err := url.Parse(publicURL)
	if err != nil {
		return
	}
	h := tcp.Hostname()
	p = tcp.Port()
	ltf.Println("try over ngrok")
	if sshTry(u, h, p) == nil {
		user, host, port = u, h, p
	}
	return
}

func ska(con *sshlib.Connect, session *ssh.Session, noGo bool) {
	if isListen("", 0, os.Getpid()) {
		con.SendKeepAliveInterval = 100
		con.SendKeepAliveMax = 3
		if noGo {
			con.SendKeepAlive(session)
			return
		}
		go con.SendKeepAlive(session)
	}
}

func setX(key, val string) {
	set := exec.Command("setx", key, val)
	// set.Stdout = os.Stdout
	PrintOk(cmd("Run", set), srcError(set.Run()))
}

func setProxy(ProxyType, ProxyServer string) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\RealVNC\vncviewer`, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	k.SetStringValue("ProxyType", ProxyType)
	k.SetStringValue("ProxyServer", ProxyServer)
}

func getProxy() (ProxyType, ProxyServer string) {
	k, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\RealVNC\vncviewer`, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	ProxyType, _, _ = k.GetStringValue("ProxyType")
	ProxyServer, _, _ = k.GetStringValue("ProxyServer")
	return
}

func sshTry(u, h, p string) (err error) {
	ltf.Printf("%s@%s:%s\n", u, h, p)
	rw, err := NewConn()
	if err != nil {
		return
	}
	defer rw.Close()
	ag := agent.NewClient(rw)
	signers, err := ag.Signers()
	if err != nil || len(signers) == 0 {
		return
	}
	config := ssh.ClientConfig{
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		// HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		HostKeyCallback: FixedHostKeys(KnownKeys...), //HostKeyCallback(Fns[KNOWN_HOSTS]),
		User:            u,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(h, p), &config)
	if err != nil {
		return
	}
	client.Close()
	return
}

func FingerprintSHA256(pubKey ssh.PublicKey) string {
	return pubKey.Type() + " " + ssh.FingerprintSHA256(pubKey)
}

func MarshalAuthorizedKey(key ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
}

func NewConn() (sock net.Conn, err error) {
	const (
		PIPE         = `\\.\pipe\`
		sshAgentPipe = "openssh-ssh-agent"
	)
	// Get env "SSH_AUTH_SOCK" and connect.
	sockPath := os.Getenv("SSH_AUTH_SOCK")
	emptySockPath := len(sockPath) == 0

	if emptySockPath {
		sock, err = pageant.NewConn()
	}

	if err != nil && !emptySockPath {
		// `sc query afunix` for some versions of Windows
		sock, err = net.Dial("unix", sockPath)
	}

	if err != nil {
		if emptySockPath {
			sockPath = sshAgentPipe
		}
		if !strings.HasPrefix(sockPath, PIPE) {
			sockPath = PIPE + sockPath
		}
		sock, err = winio.DialPipe(sockPath, nil)
	}
	return sock, err

}

func SplitHostPort(hp, host, port string) (h, p string) {
	hp = strings.ReplaceAll(hp, "*", ALL)
	h, p, err := net.SplitHostPort(hp)
	if err == nil {
		if p == "" {
			p = port
		}
		if h == "" {
			h = host
		}
		return h, p
	}
	_, err = strconv.Atoi(hp)
	if err == nil {
		// fmt.Println("host, hp")
		return host, hp
	}
	// fmt.Println("hp, port")
	if hp == "" {
		hp = host
	}
	return hp, port
}

func tryBindL(con *sshlib.Connect, hp ...string) (hphp []string, err error) {
	hphp = hp[:]
	err = fmt.Errorf("empty")
	if con == nil {
		return
	}
	if len(hphp) < 2 {
		hphp = []string{LH, strconv.Itoa(USER)}
	}
	p, er := strconv.Atoi(hphp[1])
	if er != nil {
		p = USER
	}
	if len(hphp) > 2 {
		for i := 0; i < 10; i++ {
			hphp[1] = strconv.Itoa(p)
			err = con.TCPLocalForward(net.JoinHostPort(hphp[0], hphp[1]), net.JoinHostPort(hphp[2], hphp[3]))
			PrintOk(fmt.Sprintf("%s -L %s", Image, strings.Join(hphp, ":")), err)
			if err == nil {
				return
			}
			p++
		}
		return
	}
	go func() {
		PrintOk(fmt.Sprintf("%s -D %s:%s", Image, hphp[0], hphp[1]), con.TCPDynamicForward(hphp[0], hphp[1]))
	}()
	return
}

func tryBindR(con *sshlib.Connect, hp ...string) (hphp []string, err error) {
	hphp = hp[:]
	err = fmt.Errorf("empty")
	if con == nil {
		return
	}
	if len(hphp) < 2 {
		hphp = []string{LH, strconv.Itoa(USER)}
	}
	p, er := strconv.Atoi(hphp[1])
	if er != nil {
		p = USER
	}
	if len(hphp) > 2 {
		for i := 0; i < 10; i++ {
			hphp[1] = strconv.Itoa(p)
			err = con.TCPRemoteForward(net.JoinHostPort(hphp[0], hphp[1]), net.JoinHostPort(hphp[2], hphp[3]))
			PrintOk(fmt.Sprintf("%s -R %s", Image, strings.Join(hphp, ":")), err)
			if err == nil {
				return
			}
			p++
		}
		return
	}
	go func() {
		PrintOk(fmt.Sprintf("%s -R %s:%s", Image, hphp[0], hphp[1]), con.TCPReverseDynamicForward(hphp[0], hphp[1]))
	}()
	return
}

func cgi(con *sshlib.Connect, cc, opt string, port int, b *bytes.Buffer) (hphp []string, err error) {
	hphp = parseHPHP(opt, port)
	err = fmt.Errorf("empty")
	if con == nil || cc == "" {
		return
	}
	if len(hphp) > 2 {
		// L = append(L, strings.Join(hphp, ":"))
		return tryBindL(con, hphp...)
	}
	con.Command(cc)
	time.Sleep(time.Second)
	h, p, err := net.SplitHostPort(b.String())
	b.Reset()
	if err != nil {
		return
	}
	return tryBindL(con, append(hphp, h, p)...)
}

// return h:p:h:p
func parseHPHP(opt string, port int) (res []string) {
	bp := strconv.Itoa(port)
	if opt == "" { // ""
		opt = bp
	}
	hphp := strings.Split(opt, ":")
	// h:p:h:p :p:h:p p:h:p p h
	if len(hphp) > 0 && hphp[0] == "" { // ":" ""
		hphp[0] = LH
	}
	if len(hphp) > 1 && hphp[1] == "" { // :
		hphp[1] = bp
	}

	_, er := strconv.Atoi(hphp[0])
	if er == nil { // p...
		hphp = append([]string{LH}, hphp...)
	} // h:p:h:p :p:h:p h:p h
	switch {
	case len(hphp) > 3: // h:p:h:p
		if hphp[2] == "" { // ::
			hphp[2] = LH
		}
		if hphp[3] == "" { // :::
			hphp[3] = hphp[1]
		}
		return hphp[:4]
	case len(hphp) > 2: // h:p:h
		return append(hphp, bp)
	case len(hphp) > 1: // h:p
		return hphp
	default: // h
		return append(hphp, bp)
	}
}

func VisitAll(uhp string) {
	o := ""
	flag.VisitAll(func(f *flag.Flag) {
		minus := "-"
		if actual(flag.CommandLine, f.Name) {
			minus += minus
		}
		if f.Name != "l" {
			o += fmt.Sprintf("%s%s=%s ", minus, f.Name, f.Value)
		}
	})
	ltf.Printf("%s %s%s \n", Image, o, strings.TrimSuffix(uhp, ":"+PORT))
}

type fixedHostKeys struct {
	keys []ssh.PublicKey
}

func (f *fixedHostKeys) check(hostname string, remote net.Addr, key ssh.PublicKey) error {
	if len(f.keys) == 0 {
		return fmt.Errorf("ssh: no required host keys")
	}
	km := key.Marshal()
	for _, fKey := range f.keys {
		if fKey == nil {
			continue
		}
		if bytes.Equal(km, fKey.Marshal()) {
			return nil
		}
	}
	return fmt.Errorf("ssh: no one host key from %v match %s", f.keys, FingerprintSHA256(key))
}

// FixedHostKeys returns a function for use in
// ClientConfig.HostKeyCallback to accept specific host keys.
func FixedHostKeys(keys ...ssh.PublicKey) ssh.HostKeyCallback {
	hk := &fixedHostKeys{keys}
	return hk.check
}
