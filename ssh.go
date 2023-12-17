package main

import (
	"bytes"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Microsoft/go-winio"
	"github.com/abakum/pageant"
	"github.com/blacknon/go-sshlib"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func client(user, host, port, listenAddress string) {
	ltf.Printf("%s %s@%s:%s\n", image, user, host, port)

	rw, err := NewConn()
	if err != nil {
		err = srcError(err)
		return
	}
	defer rw.Close()

	var b bytes.Buffer
	con := &sshlib.Connect{
		// ForwardAgent: true,
		Agent:  agent.NewClient(rw),
		Stdout: &b,
	}

	signers, err := sshlib.CreateSignerAgent(con.Agent)
	if err != nil || len(signers) == 0 {
		err = srcError(err)
		return
	}

	err = con.CreateClient(host, port, user, []ssh.AuthMethod{ssh.PublicKeys(signers...)})
	if err != nil {
		err = srcError(err)
		return
	}

	if len(R) == 0 {
		R = append(R, SOCKS5)
	}
	for _, v := range R {
		hphp := strings.Split(v, ":")
		switch {
		case len(hphp) > 3:
			if hphp[0] == "" {
				hphp[0] = LH
			}
			PrintOk(fmt.Sprintf("%s -R %s:%s:%s:%s", image, hphp[0], hphp[1], hphp[2], hphp[3]), con.TCPRemoteForward(net.JoinHostPort(hphp[0], hphp[1]), net.JoinHostPort(hphp[2], hphp[3])))
		case len(hphp) > 2:
			PrintOk(fmt.Sprintf("%s -R %s:%s:%s:%s", image, LH, hphp[0], hphp[1], hphp[2]), con.TCPRemoteForward(net.JoinHostPort(LH, hphp[0]), net.JoinHostPort(hphp[1], hphp[2])))
		case len(hphp) > 1:
			ltf.Printf(fmt.Sprintf("%s -R %s:%s\n", image, hphp[0], hphp[1]))
			go func() {
				con.TCPReverseDynamicForward(hphp[0], hphp[1])
			}()
		default:
			ltf.Printf(fmt.Sprintf("%s -R %s:%s\n", image, LH, hphp[0]))
			go func() {
				con.TCPReverseDynamicForward(LH, hphp[0])
			}()
		}
	}

	// Create Session
	session, err := con.CreateSession()
	if err != nil {
		err = srcError(err)
		return
	}

	if len(L) == 0 {
		L = append(L, SOCKS5)
		con.Command("hub4com!")
		ltf.Println(b.String())
		h, p, e := net.SplitHostPort(b.String())
		if e == nil {
			L = append(L, fmt.Sprintf("%d:%s:%s", RFC2217, h, p))
		}
		b.Reset()
		con.Command("vnc!")
		ltf.Println(b.String())
		h, p, e = net.SplitHostPort(b.String())
		if e == nil {
			L = append(L, fmt.Sprintf("%d:%s:%s", RFB, h, p))
		}
	}
	for _, v := range L {
		hphp := strings.Split(v, ":")
		switch {
		case len(hphp) > 3:
			if hphp[0] == "" {
				hphp[0] = LH
			}
			PrintOk(fmt.Sprintf("%s -L %s:%s:%s:%s", image, hphp[0], hphp[1], hphp[2], hphp[3]), con.TCPLocalForward(net.JoinHostPort(hphp[0], hphp[1]), net.JoinHostPort(hphp[2], hphp[3])))
		case len(hphp) > 2:
			PrintOk(fmt.Sprintf("%s -L %s:%s:%s:%s", image, LH, hphp[0], hphp[1], hphp[2]), con.TCPLocalForward(net.JoinHostPort(LH, hphp[0]), net.JoinHostPort(hphp[1], hphp[2])))
		case len(hphp) > 1:
			ltf.Printf(fmt.Sprintf("%s -D %s:%s\n", image, hphp[0], hphp[1]))
			go func() {
				con.TCPDynamicForward(hphp[0], hphp[1])
			}()
		default:
			ltf.Printf(fmt.Sprintf("%s -D %s:%s\n", image, LH, hphp[0]))
			go func() {
				con.TCPDynamicForward(LH, hphp[0])
			}()
		}
	}
	con.SendKeepAliveInterval = 100
	con.SendKeepAliveMax = 3
	con.SendKeepAlive(session)
}

func fromNgrok(publicURL, meta string) (u, h, p, listenAddress string) {
	unp := strings.Split(meta, "@")
	u = unp[0]

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
