package main

import (
	"bytes"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	_ "embed"

	"github.com/Microsoft/go-winio"
	"github.com/abakum/go-ansiterm"
	"github.com/abakum/go-sshlib"
	"github.com/abakum/menu"
	"github.com/abakum/pageant"
	"github.com/abakum/proxy"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	USER    = 1024
	REALVAB = "vncaddrbook.exe"
)

func client(user, host, port, _ string) {
	const (
		GEOMETRY = "-geometry=300x600+0+0"
		AB       = "AB"
	)
	title := fmt.Sprintf("%s@%s:%s", user, host, port)

	VisitAll(title)

	con := &sshlib.Connect{
		ForwardAgent:    A,
		TTY:             true,
		HostKeyCallback: CertCheck.CheckHostKey,
		Version:         banner(),
	}

	// con.ConnectSshAgent()
	Fatal(con.CreateClient(host, port, user, AuthMethods))

	serverVersion := string(con.Client.ServerVersion())
	Println(serverVersion)
	IsOSSH = strings.Contains(serverVersion, OSSH)
	if Cmd != "" {
		Println(Cmd, con.CommandAnsi(Cmd, !a, IsOSSH))
		return
	}

	// menu
	d := '1'
	count := 0
	items := []menu.MenuFunc{menu.Static(MENU).Prompt}

	sA := pp("A", "", !A)
	items = append(items, func(index int, pressed rune) string {
		return shellMenu(index, pressed,
			quote(Exe)+sA+" "+title,
			con)
	})

	if len(Signers) > 2 {
		items = append(items, func(index int, pressed rune) string {
			return mOMenu(index, pressed,
				fmt.Sprintf(`%s%s%s %s@%s%s`,
					quote(Fns[XTTY]),
					sA,
					pp("load", Imag, !(IsCert || !IsOSSH)),
					user,
					host,
					pp("P", port, port == "22"),
				),
				user, host, port, false)
		})

		if OpenSSH != "" {
			if O {
				d = rune('1' + len(items) - 1)
				count++
			}
			items = append(items, func(index int, pressed rune) string {
				return mOMenu(index, pressed,
					fmt.Sprintf(`%s%s %s@%s%s -o UserKnownHostsFile="%s"`, quote(OpenSSH), sA, user, host, pp("p", port, port == "22"), UserKnownHostsFile),
					user, host, port, true)
			})
		}
	}

	if actual(flag.CommandLine, "V") {
		d = rune('1'+len(items)) - 1
		count++
		opts := []string{GEOMETRY}
		if psCount(REALVAB, "", 0) == 0 {
			opts = append(opts,
				"-ViewerPath="+Exe,
				"-MinimiseToTray=0",
				"-AddressBook="+Fns[AB],
			)
		}
		vab := exec.Command(Fns[REALVAB], opts...)
		Println(cmd("Start", vab), vab.Start())
	}

	for _, o := range V {
		s := Image + " " + CGIV
		hphp, e := cgi(con, s, o, RFB)
		Println(s, strings.Join(hphp, ":"), e)
		if e != nil {
			continue
		}
		// opt := strings.Join(hphp, ":")
		items = append(items, func(index int, pressed rune) string {
			return mV(index, pressed,
				strings.Join(hphp, ":"))
		})
	}

	if actual(flag.CommandLine, "S") || len(V) > 0 {
		i5, err := strconv.Atoi(S)
		if err == nil && !isListen("", i5, 0) {
			L = append(L, S)
			// gosysproxy.SetGlobalProxy("socks=" + net.JoinHostPort(LH, S))
			if X {
				setX("all_proxy", "socks://"+net.JoinHostPort(LH, S))
				Println("setX", "all_proxy", "socks://"+net.JoinHostPort(LH, S))
			}
			ProxyType, ProxyServer := "socks", net.JoinHostPort(LH, S)
			proxy.RealSet(ProxyType, ProxyServer)
			Println("RealSet", ProxyType, ProxyServer)
			closer.Bind(func() {
				// gosysproxy.Off()
				if X {
					setX("all_proxy", "")
					Println("setX", "all_proxy", "")
				}
				proxy.RealSet("", "")
				Println("RealSet", "", "")
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
		letf.Printf("not found %s\nInstall %s\n`setupc install 0 PortName=COM#,RealPortName=COM11,EmuBR=yes,AddRTTO=1,AddRITO=1 -`\n", EMULATOR, COM0COM)
	} else {
		if actual(flag.CommandLine, "T") || actual(flag.CommandLine, "b") {
			d = rune('1'+len(items)) - 1
			count++
		}
		for _, o := range T {
			s := Image + " " + CGIT
			hphp, e := cgi(con, s, o, RFC2217)
			Println(s, strings.Join(hphp, ":"), e)
			if e != nil {
				continue
			}
			items = append(items, func(index int, pressed rune) string {
				return ttyMenu(index, pressed, hphp...)
			})
		}
	}

	ska(con)
	menu.Menu(d, count == 1 && d != '1', true, items...)
}

func pp(key, val string, empty bool) string {
	if empty {
		return ""
	}
	return " -" + key + strings.TrimRight(" "+val, " ")
}

func banner() string {
	goos := runtime.GOOS
	if goos == "windows" {
		majorVersion, minorVersion, buildNumber := windows.RtlGetNtVersionNumbers()
		goos = fmt.Sprintf("%s_%d.%d.%d", goos, majorVersion, minorVersion, buildNumber)
	}
	return strings.Join([]string{
		Imag,
		Ver,
		goos,
	}, "_")
}
func quote(s string) string {
	if strings.Contains(s, " ") {
		return fmt.Sprintf(`"%s"`, s)
	}
	return s
}

func shellMenu(index int, pressed rune, suf string, con *sshlib.Connect) string {
	r := rune('1' + index)
	switch pressed {
	case r:
		con.ShellAnsi(nil, !a)
		return string(r)
	case menu.ITEM:
		return fmt.Sprintf("%c) %s", r, suf)
	}
	return ""
}

func mV(index int, pressed rune, opt string) string {
	r := rune('1' + index)
	switch pressed {
	case r:
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
		vv := exec.Command(RealVV, append(vvO, net.JoinHostPort(hphp[0], hphp[1]))...)
		Println(cmd("Start", vv), vv.Start())
		return string(r)
	case menu.ITEM:
		return fmt.Sprintf("%c) %s", r, opt)
	}
	return ""
}

func mOMenu(index int, pressed rune, suf, user, host, port string, O bool) string {
	r := rune('1' + index)
	switch pressed {
	case r:
		mO(user, host, port, O)
		return string(r)
	case menu.ITEM:
		return fmt.Sprintf("%c) %s", r, suf)
	}
	return ""
}

func mO(user, host, port string, O bool) {
	p := "-P"
	if O {
		p = "-p"
	}
	opts := []string{}
	if A {
		opts = append(opts, "-A")
	}
	if !O && (IsCert || !IsOSSH) {
		opts = append(opts,
			"-load",
			Imag,
		)
	}
	opts = append(opts,
		"-l",
		user,
		host,
	)
	if port != "22" {
		opts = append(opts,
			p,
			port,
		)
	}

	sshExe := Fns[XTTY]
	if O {
		sshExe = OpenSSH
		opts = append(opts,
			"-o",
			fmt.Sprintf("UserKnownHostsFile=%s", UserKnownHostsFile),
		)
	}
	ki := exec.Command(sshExe, opts...)
	if O {
		ltf.Println(cmd("Run", ki))
		ki.Stdout = os.Stdout
		ki.Stderr = os.Stdout
		ki.Stdin = os.Stdin
		ki.Run()
	} else {
		Println(cmd("Start", ki), ki.Start())
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
			if Println("Try connect over - Подключаемся через LAN", sshTry(u, ip, p)) {
				user, host, port = u, ip, p
				return
			}
		}
	}
	if n {
		return
	}
	tcp, err := url.Parse(publicURL)
	if err != nil {
		return
	}
	h := tcp.Hostname()
	p = tcp.Port()
	if Println("Try connect over - Подключаемся через ngrok", sshTry(u, h, p)) {
		user, host, port = u, h, p
	}
	return
}

// KeepAlive for portforward
func ska(con *sshlib.Connect) {
	if isListen("", 0, os.Getpid()) {
		session, err := con.CreateSession()
		if err != nil {
			return
		}
		con.SendKeepAliveInterval = 100
		con.SendKeepAliveMax = 3
		go con.SendKeepAlive(session)
	}
}

func sshTry(u, h, p string) (err error) {
	ltf.Printf("%s@%s:%s\n", u, h, p)
	for _, signer := range Signers {
		config := ssh.ClientConfig{
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: CertCheck.CheckHostKey,
			User:            u,
		}
		client, err := ssh.Dial("tcp", net.JoinHostPort(h, p), &config)
		if err == nil {
			client.Close()
			AuthMethods = config.Auth
			cert, ok := signer.PublicKey().(*ssh.Certificate)
			if ok {
				IsCert = ok
				Println("Authorized by certificate", FingerprintSHA256(cert.SignatureKey))
				return nil
			}
			Println("Authorized by", FingerprintSHA256(signer.PublicKey()))
			return nil
		}
	}
	return
}

func getSigners(caSigner ssh.Signer, id string, user string) (signers []ssh.Signer) {
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
	if len(ss) < 2 {
		Println(fmt.Errorf("no keys from agent %v", err))
	}

	sshUserDir := filepath.Join(os.Getenv("USERPROFILE"), ".ssh")
	UserKnownHostsFile = filepath.Join(sshUserDir, "known_ca")
	os.MkdirAll(sshUserDir, 0700)

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
		newCA := newPub && i == 0
		if newPub {
			Println(name, os.WriteFile(name, data, FILEMODE))
			if i == 0 { // ca.pub know_ca
				bb := bytes.NewBufferString("@cert-authority * ")
				bb.Write(data)
				Println(UserKnownHostsFile, os.WriteFile(UserKnownHostsFile, bb.Bytes(), FILEMODE))
				// for putty ...they_verify_me_by_certificate
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
		signers = append(signers, certSigner)

		if newCA || newPub {
			name = filepath.Join(sshUserDir, pref+"-cert.pub")
			err = os.WriteFile(name,
				ssh.MarshalAuthorizedKey(&certificate),
				FILEMODE)
			Println(name, err)
			if i == 1 {
				if err == nil {
					// for I_verify_them_by_certificate_they_verify_me_by_certificate
					// PuTTY -load ngrokSSH user@host
					rk, _, err := registry.CreateKey(registry.CURRENT_USER,
						`SOFTWARE\SimonTatham\PuTTY\Sessions\`+Imag,
						registry.CREATE_SUB_KEY|registry.SET_VALUE)
					if err == nil {
						rk.SetStringValue("DetachedCertificate", name)
						rk.SetDWordValue("WarnOnClose", 0)
						rk.SetDWordValue("FullScreenOnAltEnter", 1)
						rk.Close()
					} else {
						Println(err)
					}
				}
				rk, _, err := registry.CreateKey(registry.CURRENT_USER,
					`SOFTWARE\SimonTatham\PuTTY\Sessions\Default%20Settings`,
					registry.CREATE_SUB_KEY|registry.SET_VALUE)
				if err == nil {
					rk.SetDWordValue("WarnOnClose", 0)
					rk.SetDWordValue("FullScreenOnAltEnter", 1)
					rk.Close()
				} else {
					Println(err)
				}
			}
		}
	}
	return
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
			Println(Image, "-L", strings.Join(hphp, ":"), err)
			if err == nil {
				return
			}
			p++
		}
		return
	}
	go func() {
		ltf.Printf("%s -D %s:%s\n", Image, hphp[0], hphp[1])
		con.TCPDynamicForward(hphp[0], hphp[1])
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
			Println(Image, "-R", strings.Join(hphp, ":"), err)
			if err == nil {
				return
			}
			p++
		}
		return
	}
	go func() {
		ltf.Printf("%s -R %s:%s\n", Image, hphp[0], hphp[1])
		con.TCPReverseDynamicForward(hphp[0], hphp[1])
	}()
	return
}

func cgi(c *sshlib.Connect, cc, opt string, port int) (hphp []string, err error) {
	hphp = parseHPHP(opt, port)
	err = fmt.Errorf("empty")
	if c == nil || cc == "" {
		return
	}
	if len(hphp) > 2 {
		// L = append(L, strings.Join(hphp, ":"))
		return tryBindL(c, hphp...)
	}
	var bs []byte
	bs, err = c.Output(cc, false)
	if err != nil {
		// Println(cc, hphp, bs, err)
		return
	}
	h, p, err := net.SplitHostPort(strings.Split(string(bs), "\n")[0])
	// Println(h, p, err)
	if err != nil {
		return
	}
	if h == ALL {
		h = LH
	}
	return tryBindL(c, append(hphp, h, p)...)
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
	ltf.Printf("%s %s%s %s\n", Image, o, strings.TrimSuffix(uhp, ":"+PORT), Cmd)
}

func setX(key, val string) {
	set := exec.Command("setx", key, val)
	Println(cmd("Run", set), set.Run())
}

func Output(c *sshlib.Connect, cmd string, pty bool) (bs []byte, err error) {
	var o bytes.Buffer
	c.Stdin = new(bytes.Buffer)
	c.Stdout = &o
	c.Stderr = io.Discard
	tty := c.TTY
	c.TTY = pty
	err = c.Command(cmd)
	c.TTY = tty
	bs = o.Bytes()
	c.Stderr = nil
	c.Stdout = nil
	c.Stdin = nil
	if err != nil {
		return
	}
	if pty {
		Println(Esc(bs))
		bs, _ = ansiterm.Strip(bs, ansiterm.WithFe(true))
	}
	return
}

func Esc(b []byte) string {
	return string(bytes.ReplaceAll(b, []byte{0x1b}, []byte{'~'}))
}
