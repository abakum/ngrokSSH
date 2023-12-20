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

	"github.com/Microsoft/go-winio"
	"github.com/abakum/pageant"
	"github.com/blacknon/go-sshlib"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func client(user, host, port, listenAddress string) {
	var (
		sock    net.Conn
		signers []ssh.Signer
		session *ssh.Session
	)
	if so == "" {
		so = sep //auto
	} else {
		sep = so //manual
	}

	VisitAll(fmt.Sprintf("%s@%s:%s", user, host, port))

	sock, err = NewConn()
	if err != nil {
		err = srcError(err)
		return
	}
	defer sock.Close()

	var b bytes.Buffer
	con := &sshlib.Connect{
		ForwardAgent: A,
		Agent:        agent.NewClient(sock),
		Stdout:       &b,
	}

	signers, err = sshlib.CreateSignerAgent(con.Agent)
	if err != nil || len(signers) == 0 {
		err = srcError(err)
		return
	}

	err = con.CreateClient(host, port, user, []ssh.AuthMethod{ssh.PublicKeys(signers...)})
	if err != nil {
		err = srcError(err)
		return
	}

	// Create Session
	session, err = con.CreateSession()
	if err != nil {
		err = srcError(err)
		return
	}

	if len(L) == 0 {
		L = append(L, SOCKS5)
	}
	cgi(con, "vnc!", vnc, RFB, &b)
	for _, o := range L {
		tryBindL(con, parseHPHP(o, USER)...)
	}

	for _, o := range R {
		tryBindR(con, parseHPHP(o, USER)...)
	}

	con.SendKeepAliveInterval = 100
	con.SendKeepAliveMax = 3

	if so == "" {
		letf.Printf("not found %s\n`setupc install 0 PortName=COM#,RealPortName=COM11,EmuBR=yes,AddRTTO=1,AddRITO=1 -`\n", EMULATOR)
	}

	po, er := cgi(con, "hub4com!", rfc2217, RFC2217, &b)
	if er != nil || so == "" || rfc2217 == "" {
		go established(image)
		go con.SendKeepAlive(session)
		title := fmt.Sprintf("%s@%s:%s", user, host, port)
		opts := []string{
			title,
			"-title",
			title,
			"-hostkey",
			hostkey,
		}
		if A {
			opts = append(opts, "-A")
		}
		ki := exec.Command(kitty, opts...)

		li.Println(cmd("Run", ki))
		err = srcError(ki.Run())
		PrintOk(cmd("Close", ki), err)
	} else {
		go con.SendKeepAlive(session)
		hphp := parseHPHP(rfc2217, RFC2217)
		hphp[1] = strconv.Itoa(po)
		tty(strings.Join(hphp, ":"))
	}
}

func fromNgrok(publicURL, meta string) (u, h, p, listenAddress string) {
	unp := strings.Split(meta, "@")
	u = un(unp[0])
	if !N {
		np := net.JoinHostPort(ALL, PORT)
		if len(unp) > 1 {
			np = unp[1]
		}
		netsPort := strings.Split(np, ":")
		p = PORT
		if len(netsPort) > 1 {
			p = netsPort[1]
		}
		nets := strings.Split(netsPort[0], ",")
		for _, ip := range nets {
			if listenAddress == "" {
				listenAddress = net.JoinHostPort(ip, p)
			}
			if sshTry(u, ip, p) == nil {
				h = ip
				return
			}
		}
	}
	tcp, err := url.Parse(publicURL)
	if err != nil {
		return
	}
	p = tcp.Port()
	if sshTry(u, tcp.Hostname(), p) == nil {
		h = tcp.Hostname()
	}
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
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            u,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(h, p), &config)
	if err != nil {
		return
	}
	client.Close()
	return
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
	h, p, e := net.SplitHostPort(hp)
	if e == nil {
		return h, p
	}
	_, e = strconv.Atoi(hp)
	if e == nil {
		return host, hp
	}
	return hp, port
}

func tryBindL(con *sshlib.Connect, hphp ...string) (p int, err error) {
	if len(hphp) < 2 {
		hphp = []string{LH, strconv.Itoa(USER)}
	}
	p, er := strconv.Atoi(hphp[1])
	if er != nil {
		p = USER
	}
	if len(hphp) > 2 {
		for i := 0; i < 3; i++ {
			err = con.TCPLocalForward(net.JoinHostPort(hphp[0], strconv.Itoa(p)), net.JoinHostPort(hphp[2], hphp[3]))
			if err == nil {
				ltf.Printf("%s -L %s:%d:%s:%s", image, hphp[0], p, hphp[2], hphp[3])
				return
			}
			p++
		}
		return
	}
	go func() {
		ltf.Printf("%s -D %s:%s", image, hphp[0], hphp[1])
		err = con.TCPDynamicForward(hphp[0], hphp[1])
		PrintOk("TCPDynamicForward", err)
	}()
	return
}

func tryBindR(con *sshlib.Connect, hphp ...string) (p int, err error) {
	if len(hphp) < 2 {
		hphp = []string{LH, strconv.Itoa(USER)}
	}
	p, er := strconv.Atoi(hphp[1])
	if er != nil {
		p = USER
	}
	if len(hphp) > 2 {
		for i := 0; i < 3; i++ {
			err = con.TCPRemoteForward(net.JoinHostPort(hphp[0], strconv.Itoa(p)), net.JoinHostPort(hphp[2], hphp[3]))
			if err == nil {
				ltf.Printf("%s -R %s:%d:%s:%s", image, hphp[0], p, hphp[2], hphp[3])
				return
			}
			p++
		}
		return
	}
	go func() {
		ltf.Printf("%s -R %s:%s", image, hphp[0], hphp[1])
		err = con.TCPReverseDynamicForward(hphp[0], hphp[1])
		PrintOk("TCPDynamicForward", err)
	}()
	return
}

func cgi(con *sshlib.Connect, cc, opt string, port int, b *bytes.Buffer) (po int, err error) {
	if opt == "" {
		return
	}
	hphp := parseHPHP(opt, port)
	if len(hphp) > 2 {
		// L = append(L, strings.Join(hphp, ":"))
		return tryBindL(con, hphp...)
	}
	con.Command(cc)
	time.Sleep(time.Second)
	h, p, e := net.SplitHostPort(b.String())
	b.Reset()
	if e != nil {
		return 0, err
	}
	// L = append(L, strings.Join(append(hphp, h, p), ":"))
	return tryBindL(con, append(hphp, h, p)...)
}

func parseHPHP(opt string, port int) (res []string) {
	if opt == "" {
		return
	}
	bp := strconv.Itoa(port)
	hphp := strings.Split(opt, ":")
	// h:p:h:p :p:h:p p:h:p p h
	if len(hphp) > 0 && hphp[0] == "" { // :
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
		if f.Name != "l" {
			o += fmt.Sprintf("-%s=%s ", f.Name, f.Value)
		}
	})
	ltf.Printf("%s %s%s \n", image, o, uhp)
}
