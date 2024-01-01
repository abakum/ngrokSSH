package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	//go:embed authorized_keys
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

	for _, o := range R {
		tryBindR(con, parseHPHP(o, USER)...)
	}

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
	for _, o := range L {
		tryBindL(con, parseHPHP(o, USER)...)
	}

	if len(V) > 0 {
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
		for _, o := range V {
			hphp, ev := cgi(con, CGIV, o, RFB, &b)
			if ev != nil {
				continue
			}
			menuVoption = append(menuVoption, strings.Join(hphp, ":"))
		}
		opts := []string{GEOMETRY}
		if psCount(REALVAB, "", 0) == 0 {
			opts = append(opts,
				"-ViewerPath="+Exe,
				"-MinimiseToTray=0",
				"-AddressBook="+Fns[AB],
			)
		}
		vab := exec.Command(Fns[REALVAB], opts...)
		li.Println(cmd("Start", vab), vab.Start())
		if len(menuVoption) > 0 {
			ska(con, session, false)
			for {
				menuV := wmenu.NewMenu("Choose target for console - выбери цель подключения консоли `VNC`")
				menuV.Action(func(opts []wmenu.Opt) error {
					for _, opt := range opts {
						menuVid = opt.ID
						hphp := parseHPHP(opt.Text, RFB)
						vv := exec.Command(Fns[REALVV], append(vvO, net.JoinHostPort(hphp[0], hphp[1]))...)
						PrintOk(cmd("Start", vv), vv.Start())
						return nil
					}
					return nil
				})
				for i, opt := range menuVoption {
					menuV.Option(opt, nil, i == menuVid, nil)
				}
				if menuV.Run() != nil {
					return
				}
			}
		} else {
			ska(con, session, true)
			return
		}
	}

	if len(T) > 0 {
		if So == "" {
			letf.Printf("not found %s\n`setupc install 0 PortName=COM#,RealPortName=COM11,EmuBR=yes,AddRTTO=1,AddRITO=1 -`\n", EMULATOR)
		} else {
			for _, o := range T {
				hphp, e := cgi(con, CGIT, o, RFC2217, &b)
				if e != nil {
					continue
				}
				MenuToption = append(MenuToption, strings.Join(hphp, ":"))
			}
			if len(MenuToption) > 0 {
				ska(con, session, false)
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
			} else {
				ska(con, session, true)
				return
			}
		}
	}

	opts := []string{
		title,
		"-title",
		title,
		"-hostkey",
		strings.Split(Known_host, " ")[2],
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
			fmt.Sprintf("UserKnownHostsFile=%s", filepath.Join(Cwd, ROOT, "known_host")),
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
	} else {
		go established(Image)
	}
	li.Println(cmd("Run", ki))
	Err = srcError(ki.Run())
	PrintOk(cmd("Close", ki), Err)
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
		HostKeyCallback: HostKeyCallback(Known_host),
		User:            u,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(h, p), &config)
	if err != nil {
		return
	}
	client.Close()
	return
}

func HostKeyCallback(tk string) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		ak := "* " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
		if tk != ak {
			Err = fmt.Errorf("hostname %s, remote %v\nexpected %q\nbut  got %q", hostname, remote, tk, ak)
			ltf.Println(Err)
			return Err
		}

		return nil
	}
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
	h, p, err := net.SplitHostPort(hp)
	if err == nil {
		return h, p
	}
	_, err = strconv.Atoi(hp)
	if err == nil {
		return host, hp
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
			hphp[3] = bp
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
