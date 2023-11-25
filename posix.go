//go:build !windows
// +build !windows

package main

import "os/exec"
gossh "golang.org/x/crypto/ssh"

func SubsystemHandlerAgent(s ssh.Session) {
	l, err := NewAgentListener(s)
	if err != nil {
		return
	}
	defer l.Close()
	go doner(l, s)
	ssh.ForwardAgentConnections(l, s)
}

// NewAgentListener sets up a temporary Unix socket that can be communicated
// to the session environment and used for forwarding connections.
func NewAgentListener(s ssh.Session) (net.Listener, error) {
	for _, e := range s.Environ() {
		if strings.HasPrefix(e, SSH_AUTH_SOCK) {
			l, err := net.Listen("unix",strings.TrimPrefix(e, SSH_AUTH_SOCK))
			if err != nil {
				return nil, err
			}
			return l, nil
		}
	}
	return nil, fmt.Errorf("not found %s", SSH_AUTH_SOCK)
}


func aKeys() []string {
	return []string{
		path.Join(cwd, authorizedKeys),
		path.Join(os.Getenv("HOME"), ".ssh", authorizedKeys),
		path.Join("/etc/dropbear", authorizedKeys),
	}
}

func hKey(_, sshHostKey string) (pri string) {
	for _, key := range []string{
		"ssh_host_ecdsa_key",
		"ssh_host_ed25519_key",
		sshHostKey,
	} {
		pri = path.Join("/etc/ssh", key)
		_, err := os.Stat(pri)
		if err == nil {
			break
		}
	}
	return
}

proc shellArgs(commands []string) []string{
 return commands[:]
}

func shArgs(commands []string) (args []string) {
	const SH = "/bin/sh"
	path := ""
	var err error
	for _, shell := range []string{
		os.Getenv("SHELL"),
		"/bin/bash",
		"/usr/local/bin/bash",
		"/bin/sh",
		"bash",
		"sh",
	} {
		if path, err = exec.LookPath(shell); err == nil {
			break
		}
	}
	if path == "" {
		path = SH
	}

	args = []string{path}
	if len(commands) > 0 {
		args = append(args, "-c")
		args = append(args, commands...)
	}
	return
}

func allDone(ppid int) (err error){
	log.Println("allDone", ppid)
	pgid, err := syscall.Getpgid(ppid)
    if err == nil {
		err=syscall.Kill(-pgid, 15)
        if err==nil{ 
			log.Println("pgid", pgid, "done")
			return
		}
    }
	return pDone(ppid)
}

func UnloadEmbedded(_, _ string) error{
	return nil
}

func env(s ssh.Session, shell string) (e []string) {
	e=s.Environ
	ra, ok := s.RemoteAddr().(*net.TCPAddr)
	if ok {
		la, ok := s.LocalAddr().(*net.TCPAddr)
		if ok {
			e = append(e,
				fmt.Sprintf("%s=%s %d %d", "SSH_CLIENT", ra.IP, ra.Port, la.Port),
				fmt.Sprintf("%s=%s %d %s %d", "SSH_CONNECTION", ra.IP, ra.Port, la.IP, la.Port),
			)
		}
	}
	e = append(e,
		"LOGNAME="+s.User(),
	)
	return
}
