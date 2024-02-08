package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"

	_ "embed"

	"github.com/Microsoft/go-winio"
	"github.com/abakum/go-ansiterm"
	"github.com/abakum/menu"
	windowsconsole "github.com/abakum/ngrokSSH/windows"
	"github.com/abakum/pageant"
	"github.com/abakum/proxy"
	"github.com/blacknon/go-sshlib"
	termm "github.com/moby/term"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/sys/windows"
)

const (
	USER    = 1024
	REALVAB = "vncaddrbook.exe"
)

func client(user, host, port, listenAddress string) {
	const (
		GEOMETRY = "-geometry=300x600+0+0"
		AB       = "AB"
	)
	var (
		sock    net.Conn
		signers []ssh.Signer
		err     error
	)
	title := fmt.Sprintf("%s@%s:%s", user, host, port)

	VisitAll(title)

	sock, err = NewConn()
	Fatal(err)
	defer sock.Close()

	con := &sshlib.Connect{
		ForwardAgent: A,
		Agent:        agent.NewClient(sock),
		TTY:          true,
	}

	signers, err = sshlib.CreateSignerAgent(con.Agent)
	Fatal(err)
	FatalOr("len(signers) < 1", len(signers) < 1)

	Fatal(con.CreateClient(host, port, user, []ssh.AuthMethod{ssh.PublicKeys(signers...)}))
	serverVersion := string(con.Client.ServerVersion())
	Println(serverVersion)
	if Cmd != "" {
		Println(Cmd, Command(con, Cmd, strings.Contains(serverVersion, Imag)))
		return
	}

	// menu
	d := '1'
	count := 0
	items := []menu.MenuFunc{menu.Static(MENU).Prompt}

	sA := ""
	if A {
		sA = " -A"
	}
	items = append(items, func(index int, pressed rune) string {
		return shellMenu(index, pressed,
			quote(Exe)+sA+" "+title,
			con)
	})

	hostkey := ""
	if len(KnownKeys) > 0 {
		hostkey = " -hostkey " + ssh.FingerprintSHA256(KnownKeys[0])
	}
	items = append(items, func(index int, pressed rune) string {
		return mOMenu(index, pressed,
			quote(Fns[KITTY])+sA+" "+title+hostkey,
			title, user, host, port, false)
	})

	if OpenSSH != "" {
		if O {
			d = rune('1' + len(items) - 1)
			count++
		}
		items = append(items, func(index int, pressed rune) string {
			return mOMenu(index, pressed,
				fmt.Sprintf(`%s%s %s@%s -p %s -o UserKnownHostsFile="%s"`, quote(OpenSSH), sA, user, host, port, KnownHosts),
				title, user, host, port, true)
		})
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
		ok, err := AllowVTP(os.Stdout)
		if err == nil && !ok && !a {
			Println("choco install ansicon")
		}
		Shell(con)
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

func mOMenu(index int, pressed rune, suf, title, user, host, port string, O bool) string {
	r := rune('1' + index)
	switch pressed {
	case r:
		mO(title, user, host, port, O)
		return string(r)
	case menu.ITEM:
		return fmt.Sprintf("%c) %s", r, suf)
	}
	return ""
}

func mO(title, user, host, port string, O bool) {
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
			fmt.Sprintf("UserKnownHostsFile=%s", KnownHosts),
		}
	}
	if A {
		opts = append(opts, "-A")
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
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: FixedHostKeys(KnownKeys...),
		User:            u,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(h, p), &config)
	if err != nil {
		return
	}
	// Println(string(client.ServerVersion()))
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
	bs, err = Output(c, cc, false)
	if err != nil {
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

func setX(key, val string) {
	set := exec.Command("setx", key, val)
	Println(cmd("Run", set), set.Run())
}

func setupShell(c *sshlib.Connect) (err error) {

	// Request tty
	err = sshlib.RequestTty(c.Session)
	if err != nil {
		return err
	}

	// x11 forwarding
	if c.ForwardX11 {
		err = c.X11Forward(c.Session)
		if err != nil {
			letf.Println(err)
		}
	}
	err = nil

	// ssh agent forwarding
	if c.ForwardAgent {
		c.ForwardSshAgent(c.Session)
	}

	return
}

// Shell connect login shell over ssh.
func Shell(c *sshlib.Connect) (err error) {

	if c.Session == nil {
		c.Session, err = c.CreateSession()
		if err != nil {
			return
		}
	}
	defer func() { c.Session = nil }()

	// setup
	err = setupShell(c)
	if err != nil {
		return
	}

	// Set Stdin, Stdout, Stderr...
	std := newIOE()
	defer std.Close()
	c.Session.Stdin = std.rc

	c.Session.Stdout = os.Stdout
	c.Session.Stdout = os.Stderr
	if !a {
		wo, do, err := stdOE(os.Stdout)
		if err == nil {
			//Win7
			defer do.Close()
			c.Session.Stdout = wo
		}

		we, de, err := stdOE(os.Stderr)
		if err == nil {
			defer de.Close()
			c.Session.Stderr = we
		}
	}
	// Start shell
	err = c.Session.Shell()
	if err != nil {
		return
	}

	// keep alive packet
	go c.SendKeepAlive(c.Session)

	err = c.Session.Wait()
	return
}

// Command connect and run command over ssh.
// Output data is processed by channel because it is executed in parallel. If specification is troublesome, it is good to generate and process session from ssh package.
func Command(c *sshlib.Connect, command string, ptyTrue bool) (err error) {
	// create session
	if c.Session == nil {
		c.Session, err = c.CreateSession()
		if err != nil {
			return
		}
	}
	defer func() { c.Session = nil }()

	// setup options
	err = setOption(c, c.Session)
	if err != nil {
		return
	}

	// Set Stdin, Stdout, Stderr...
	std := newIOE()
	defer std.Close()
	c.Session.Stdin = std.rc

	c.Session.Stdout = os.Stdout
	c.Session.Stdout = os.Stderr
	if !a {
		wo, do, err := stdOE(os.Stdout)
		if err == nil {
			//Win7
			defer do.Close()
			c.Session.Stdout = wo
		}

		we, de, err := stdOE(os.Stderr)
		if err == nil {
			defer de.Close()
			c.Session.Stderr = we
		}
	}
	if !ptyTrue {
		// fix pty of OpenSSH sshd
		command += "&timeout/t 1"
	}

	// Run Command
	err = c.Session.Run(command)

	return
}

func setOption(c *sshlib.Connect, session *ssh.Session) (err error) {
	// Request tty
	if c.TTY {
		err = sshlib.RequestTty(session)
		if err != nil {
			return err
		}
	}

	// ssh agent forwarding
	if c.ForwardAgent {
		c.ForwardSshAgent(session)
	}

	// x11 forwarding
	if c.ForwardX11 {
		err = c.X11Forward(session)
		if err != nil {
			letf.Println(err)
		}
		err = nil
	}

	return
}

func stdIn() (trg io.ReadCloser, err error) {
	src := os.Stdin
	var (
		mode    uint32
		emulate bool
	)

	fd := windows.Handle(src.Fd())
	if err := windows.GetConsoleMode(fd, &mode); err == nil {
		// Validate that winterm.ENABLE_VIRTUAL_TERMINAL_INPUT is supported, but do not set it.
		if err = windows.SetConsoleMode(fd, mode|windows.ENABLE_VIRTUAL_TERMINAL_INPUT); err != nil {
			emulate = true
		}
		// Unconditionally set the console mode back even on failure because SetConsoleMode
		// remembers invalid bits on input handles.
		_ = windows.SetConsoleMode(fd, mode)
	}

	if emulate {
		return windowsconsole.NewAnsiReaderDuplicate(src)
	}
	return nil, ErrWin10
}

func AllowVTI() (ok bool, err error) {
	src := os.Stdin
	var (
		mode uint32
	)
	fd := windows.Handle(src.Fd())
	if err := windows.GetConsoleMode(fd, &mode); err == nil {
		// isConsole
		// Validate that winterm.ENABLE_VIRTUAL_TERMINAL_INPUT is supported, but do not set it.
		ok = windows.SetConsoleMode(fd, mode|windows.ENABLE_VIRTUAL_TERMINAL_INPUT) == nil
		// Unconditionally set the console mode back even on failure because SetConsoleMode
		// remembers invalid bits on input handles.
		_ = windows.SetConsoleMode(fd, mode)
	}
	return
}

var ErrWin10 = errors.New("no need emulate")

func stdOE(src *os.File) (io.Writer, *os.File, error) {
	var (
		mode    uint32
		emulate bool
	)

	fd := windows.Handle(src.Fd())
	if err := windows.GetConsoleMode(fd, &mode); err == nil {
		// Validate winterm.DISABLE_NEWLINE_AUTO_RETURN is supported, but do not set it.
		if err = windows.SetConsoleMode(fd, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.DISABLE_NEWLINE_AUTO_RETURN); err != nil {
			emulate = true
		} else {
			_ = windows.SetConsoleMode(fd, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
		}
	}

	if emulate {
		return windowsconsole.NewAnsiWriterFileDuplicate(src)
	}
	return nil, nil, ErrWin10
}

func AllowVTP(src *os.File) (ok bool, err error) {
	var (
		mode uint32
	)
	if src == nil {
		src = os.Stdout
	}
	fd := windows.Handle(src.Fd())
	err = windows.GetConsoleMode(fd, &mode)
	if err == nil {
		// isConsole
		ok = windows.SetConsoleMode(fd, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING|windows.DISABLE_NEWLINE_AUTO_RETURN) == nil
		_ = windows.SetConsoleMode(fd, mode)
	}
	return
}
func EnableVTP() (ok bool) {
	var (
		mode uint32
	)
	fd := windows.Handle(os.Stdout.Fd())
	if err := windows.GetConsoleMode(fd, &mode); err == nil {
		// isConsole
		ok = windows.SetConsoleMode(fd, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING) == nil
	}
	return
}

type ioe struct {
	i, o, e *termm.State
	rc      io.ReadCloser
}

func newIOE() (s *ioe) {
	s = &ioe{}

	termm.StdStreams()
	s.i, _ = termm.SetRawTerminal(os.Stdin.Fd())
	s.o, _ = termm.SetRawTerminalOutput(os.Stdout.Fd())
	s.e, _ = termm.SetRawTerminalOutput(os.Stderr.Fd())
	// for Win10 no need emulation VTP but need close duble of os.Stdin
	// to unblock input after return
	s.rc, _ = windowsconsole.NewAnsiReaderDuplicate(os.Stdin)
	return
}

func (s *ioe) Close() {
	if s == nil {
		return
	}
	if s.rc != nil {
		if s.rc.Close() == nil {
			s.rc = nil
		}
	}
	if s.e != nil {
		if termm.RestoreTerminal(os.Stderr.Fd(), s.e) == nil {
			s.e = nil
		}
	}
	if s.o != nil {
		if termm.RestoreTerminal(os.Stdout.Fd(), s.o) == nil {
			s.o = nil
		}
	}
	if s.i != nil {
		if termm.RestoreTerminal(os.Stdin.Fd(), s.i) == nil {
			s.i = nil
		}
	}
	s = nil
}

func Output(c *sshlib.Connect, cmd string, pty bool) (bs []byte, err error) {
	if c.Session == nil {
		c.Session, err = c.CreateSession()
		if err != nil {
			return
		}
	}
	c.TTY = pty

	defer func() {
		c.Session = nil
		c.TTY = true
	}()

	// setup options
	err = setOption(c, c.Session)
	if err != nil {
		return
	}
	bs, err = c.Session.Output(cmd)
	if err != nil {
		return
	}
	if pty {
		Println(Esc(bs))
		// bs, _ = ansi.Strip(bs)
		bs, _ = ansiterm.Strip(bs, ansiterm.WithFe(true))
	}
	return
}

func Output2(c *sshlib.Connect, cmd string, pty bool) (bs []byte, err error) {
	var o bytes.Buffer
	c.Stdin = new(bytes.Buffer)
	c.Stdout = &o
	c.Stderr = io.Discard
	c.TTY = pty
	err = c.Command(cmd)
	c.TTY = true
	bs = o.Bytes()
	c.Stderr = nil
	c.Stdout = nil
	c.Stdin = nil
	if err != nil {
		return
	}
	if pty {
		Println(Esc(bs))
		// bs, _ = ansi.Strip(bs)
		bs, _ = ansiterm.Strip(bs, ansiterm.WithFe(true))

	}
	return
}

// bytesToHex converts a slice of bytes to a human-readable string.
func Esc(b []byte) string {
	return string(bytes.ReplaceAll(b, []byte{0x1b}, []byte{'~'}))
}
