package main

import (
	"bytes"
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
	windowsconsole "github.com/abakum/ngrokSSH/windows"
	"github.com/abakum/pageant"
	"github.com/abakum/proxy"
	"github.com/blacknon/go-sshlib"
	"github.com/eiannone/keyboard"
	termm "github.com/moby/term"
	"github.com/xlab/closer"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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
		sock        net.Conn
		signers     []ssh.Signer
		menuVoption []string
		menuId      = 0
		err         error
	)
	title := fmt.Sprintf("%s@%s:%s", user, host, port)

	VisitAll(title)

	sock, err = NewConn()
	Fatal(err)
	defer sock.Close()

	con := &sshlib.Connect{
		ForwardAgent: A,
		Agent:        agent.NewClient(sock),
	}

	signers, err = sshlib.CreateSignerAgent(con.Agent)
	Fatal(err)
	FatalOr("len(signers) < 1", len(signers) < 1)

	Fatal(con.CreateClient(host, port, user, []ssh.AuthMethod{ssh.PublicKeys(signers...)}))
	Println(string(con.Client.ServerVersion()))

	if Cmd != "" {
		con.TTY = true
		con.Stdin, con.Stdout, con.Stderr = termm.StdStreams()
		Println(Cmd, con.Command(Cmd))
		return
	}

	for _, o := range V {
		hphp, e := cgi(con, Image+" "+CGIV, o, RFB)
		if e != nil {
			continue
		}
		menuVoption = append(menuVoption, strings.Join(hphp, ":"))
	}

	if actual(flag.CommandLine, "S") || len(menuVoption) > 0 {
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
		letf.Printf("not found %s\n`setupc install 0 PortName=COM#,RealPortName=COM11,EmuBR=yes,AddRTTO=1,AddRITO=1 -`\n", EMULATOR)
	} else {
		for _, o := range T {
			hphp, e := cgi(con, Image+" "+CGIT, o, RFC2217)
			if e != nil {
				continue
			}
			MenuToption = append(MenuToption, strings.Join(hphp, ":"))
		}
	}

	ska(con)
	o := 1
	if OpenSSH != "" {
		o++
	}
	switch {
	case actual(flag.CommandLine, "T") || actual(flag.CommandLine, "b"):
		menuId = len(menuVoption) + 1 + o
		if len(MenuToption) == 1 {
			tty(parseHPHP(MenuToption[0], RFC2217)...)
		}
	case actual(flag.CommandLine, "V"):
		menuId = 1 + o
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
		if len(menuVoption) == 1 {
			mV(menuVoption[0])
		}
	default:
		if O {
			menuId = 2
		}
	}
	hostkey := ""
	if len(KnownKeys) > 0 {
		hostkey = " -hostkey " + ssh.FingerprintSHA256(KnownKeys[0])
	}
	sA := ""
	if A {
		sA = " -A"
	}
	items := []func(index int) string{}
	items = append(items, func(index int) string {
		if index > -1 {
			return fmt.Sprintf(`%d) %s%s %s`, index+1, quote(Exe), sA, title)
		}
		mPS(con)
		return ""
	})
	items = append(items, func(index int) string {
		if index >= 1 {
			return fmt.Sprintf(`%d) %s%s %s%s`, index+1, quote(Fns[KITTY]), sA, title, hostkey)
		}
		mO(title, user, host, port, false)
		return ""
	})
	if OpenSSH != "" {
		items = append(items, func(index int) string {
			if index > -1 {
				return fmt.Sprintf(`%d) %s%s %s@%s -p %s -o UserKnownHostsFile="%s"`, index+1, quote(OpenSSH), sA, user, host, port, KnownHosts)
			}
			mO(title, user, host, port, true)
			return ""
		})
	}
	for _, opt := range menuVoption {
		items = append(items, func(index int) string {
			if index > -1 {
				return fmt.Sprintf("%d) %s", index+1, opt)
			}
			mV(opt)
			return ""
		})
	}
	for _, opt := range MenuToption {
		items = append(items, func(index int) string {
			if index > -1 {
				return fmt.Sprintf("%d) %s", index+1, opt)
			}
			tty(parseHPHP(opt, RFC2217)...)
			return ""
		})
	}
	d := rune('1' + menuId)
	hit := menuId > 0
	menu(func(index int, d rune) string { return MENU }, d, hit, false, true, items...)
}

func quote(s string) string {
	if strings.Contains(s, " ") {
		return fmt.Sprintf(`"%s"`, s)
	}
	return s
}

func menu(prompt func(index int, d rune) string, d rune, keyEnter, once, exitOnTypo bool, items ...func(index int) string) {
	var (
		key   keyboard.Key
		err   error
		r     rune
		index int
	)
	for {
		// Print menu
		fmt.Println()
		newD := false // search GT
		for i, item := range items {
			s := item(i) //get menu item
			if len(s) < 1 {
				continue
			}
			newD = strings.HasPrefix(s, GT)
			if newD {
				if len(s) < 2 {
					continue
				}
				s = s[1:]
				d = []rune(s)[0]
			}
		}
		for i, item := range items { //print menu
			s := item(i) //get menu item
			if len(s) < 1 {
				continue
			}
			mark := " "
			if strings.HasPrefix(s, GT) { // new d
				if len(s) < 2 {
					continue
				}
				mark = GT
				s = s[1:]
			}
			if d == []rune(s)[0] {
				mark = Gt
			}
			fmt.Printf("%s%s\n", mark, s)
		}
		fmt.Print(prompt(index, d), Gt)
		if keyEnter {
			r = d
		} else {
			r, key, err = keyboard.GetSingleKey()
			if err != nil {
				fmt.Println(Bug)
				return
			}
			if key == keyboard.KeyEnter {
				r = d
			}
		}
		keyEnter = false
		d = r
		fmt.Printf("%c\n", d)
		ok := false
	doit:
		for i, item := range items {
			s := item(i) //get menu item
			if len(s) < 1 {
				continue
			}
			if strings.HasPrefix(s, GT) { //ignore GT from item
				if len(s) < 2 {
					continue
				}
				s = s[1:]
			}
			ok = d == []rune(s)[0]
			if ok {
				if item(-1) == "exit" || once { // run func of menu item
					return
				}
				break doit
			}
		}
		if exitOnTypo && !ok {
			return
		}
	}
}

func mPS(con *sshlib.Connect) {
	Shell(con)
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
	vv := exec.Command(RealVV, append(vvO, net.JoinHostPort(hphp[0], hphp[1]))...)
	Println(cmd("Start", vv), vv.Start())
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

func cgi(con *sshlib.Connect, cc, opt string, port int) (hphp []string, err error) {
	hphp = parseHPHP(opt, port)
	err = fmt.Errorf("empty")
	if con == nil || cc == "" {
		return
	}
	if len(hphp) > 2 {
		// L = append(L, strings.Join(hphp, ":"))
		return tryBindL(con, hphp...)
	}
	var o bytes.Buffer
	con.Stdin = new(bytes.Buffer)
	con.Stdout = &o
	con.Stderr = io.Discard
	Println(cc, con.Command(cc), o.String())
	con.Stdin = nil
	con.Stdout = nil
	con.Stderr = nil
	h, p, err := net.SplitHostPort(o.String())
	if err != nil {
		return
	}
	if h == ALL {
		h = LH
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
	// Set Stdin, Stdout, Stderr...
	c.Session.Stdin = c.Stdin
	c.Session.Stdout = c.Stdout
	c.Session.Stderr = c.Stderr

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
	defer func() {
		// c.Session.Close()
		c.Session = nil
	}()

	si, err := termm.SetRawTerminal(os.Stdin.Fd())
	if err != nil {
		return
	}
	defer termm.RestoreTerminal(os.Stdin.Fd(), si)

	so, err := termm.SetRawTerminalOutput(os.Stdout.Fd())
	if err != nil {
		return
	}
	defer termm.RestoreTerminal(os.Stdout.Fd(), so)

	se, err := termm.SetRawTerminalOutput(os.Stderr.Fd())
	if err != nil {
		return
	}
	defer termm.RestoreTerminal(os.Stderr.Fd(), se)

	// c.Stdin, c.Stdout, c.Stderr = termm.StdStreams()
	_, c.Stdout, c.Stderr = termm.StdStreams()

	stdin, err := windowsconsole.NewAnsiReaderDuplicate(os.Stdin)
	if err != nil {
		return
	}
	defer stdin.Close()

	c.Stdin = stdin

	defer func() {
		c.Stdin, c.Stdout, c.Stderr = nil, nil, nil
	}()

	// setup
	err = setupShell(c)
	if err != nil {
		return
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
func Command(c *sshlib.Connect, command string) (err error) {
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
	if c.Stdin != nil {
		w, _ := c.Session.StdinPipe()
		go io.Copy(w, c.Stdin)
	} else {
		stdin := sshlib.GetStdin()
		c.Session.Stdin = stdin
	}

	if c.Stdout != nil {
		or, _ := c.Session.StdoutPipe()
		go io.Copy(c.Stdout, or)
	} else {
		c.Session.Stdout = os.Stdout
	}

	if c.Stderr != nil {
		er, _ := c.Session.StderrPipe()
		go io.Copy(c.Stderr, er)
	} else {
		c.Session.Stderr = os.Stderr
	}

	// Run Command
	c.Session.Run(command)

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
