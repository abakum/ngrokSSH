//go:build !windows
// +build !windows

package main

import "os/exec"

proc shellArgs(commands []string) []string{
 return commands[:]
}

func shArgs(commands []string) (args []string) {
	const SH = "/bin/sh"
	path := ""
	var err error
	for _, shell := range []string{"/bin/bash", "/usr/local/bin/bash", "/bin/sh", "bash", "sh"} {
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