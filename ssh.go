package main

import (
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/abakum/pageant"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func client(u, h, p string) {
	ltf.Printf("%s@%s:%s\n", u, h, p)
}

func fromNgrok(publicURL, meta string) (u, h, p string) {
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

func sshTry(user, host, port string) (err error) {
	rw, err := pageant.NewConn()
	if err != nil {
		return
	}
	defer rw.Close()
	ag := agent.NewClient(rw)
	if err != nil {
		return
	}
	signers, err := ag.Signers()
	if err != nil || len(signers) == 0 {
		return
	}
	config := ssh.ClientConfig{
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signers...)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		User:            user,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(host, port), &config)
	if err != nil {
		return
	}
	client.Close()
	return
}

func contains(n, ip string) bool {
	network, err := netip.ParsePrefix(n)
	if err != nil {
		return false
	}
	ipContains, err := netip.ParsePrefix(ip)
	if err != nil {
		return false
	}
	return network.Contains(ipContains.Addr())
}
