//go:build !windows
// +build !windows

package main

import "os/exec"

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

func osEnv(_ ssh.Session, _ string) (e []string) {
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