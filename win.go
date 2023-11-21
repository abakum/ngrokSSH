//go:build windows
// +build windows

package main

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"github.com/gliderlabs/ssh"
)

func aKeys() []string {
	return []string{
		filepath.Join(os.Getenv("ALLUSERSPROFILE"), administratorsAuthorizedKeys),
		filepath.Join(os.Getenv("USERPROFILE"), ".ssh", authorizedKeys),
		filepath.Join(cwd, authorizedKeys),
	}
}

func hKey(cwd, sshHostKey string) (pri string) {
	for _, dir := range []string{
		os.Getenv("ALLUSERSPROFILE"),
		cwd,
	} {
		for _, key := range []string{
			"ssh_host_ecdsa_key",
			"ssh_host_ed25519_key",
			sshHostKey,
		} {
			pri = filepath.Join(dir, key)
			_, err := os.Stat(pri)
			if err == nil {
				break
			}
		}
	}
	return
}

func osEnv(s ssh.Session, shell string) (e []string) {
	ptyReq, _, isPty := s.Pty()
	if isPty {
		if ptyReq.Term != "" {
			e = append(e,
				"TERM="+ptyReq.Term,
			)
		}
		e = append(e,
			"SSH_TTY=windows-pty",
		)
	}
	e = append(e,
		fmt.Sprintf(`HOME=%s%s\%s`, os.Getenv("HOMEDRIVE"), os.Getenv("HOMEPATH"), s.User()),
		fmt.Sprintf("PROMPT=%s@%s$S$P$G", s.User(), os.Getenv("COMPUTERNAME")),
		fmt.Sprintf("SHELL=%s", shell),
	)
	return
}

func psArgs(commands []string) (args []string) {
	args = []string{"powershell.exe", "-NoProfile", "-NoLogo"}
	if len(commands) > 0 {
		args = append(args,
			"-NonInteractive",
			"-Command")
		args = append(args, commands...)
	} else {
		args = append(args, "-Mta") //for Win7
	}
	return
}
func shellArgs(commands []string) (args []string) {
	const SH = "ssh-shellhost.exe"

	path := ""
	var err error
	for _, shell := range []string{filepath.Join(os.Getenv("ProgramFiles"), BIN, SH), SH} {
		log.Println(shell)
		if path, err = exec.LookPath(shell); err == nil {
			break
		}
	}
	shell := len(commands) == 1
	if err != nil { //fallback
		if shell {
			commands = []string{}
		}
		args = psArgs(commands)
		return
	}
	args = []string{path}
	opt := "-c"
	if shell {
		opt = "---pty"
	}
	args = append(args, opt)
	args = append(args, commands...)
	return
}

func shArgs(commands []string) (args []string) {
	const SH = "cmd.exe"
	path := ""
	var err error
	for _, shell := range []string{
		os.Getenv("ComSpec"),
		SH,
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
		args = append(args, "/c")
		args = append(args, commands...)
	}
	return
}

// https://gist.github.com/gekigek99/94f3629e929d514ca6eed55e111ae442
// getTreePids will return a list of pids that represent the tree of process pids originating from the specified one.
// (they are ordered: [parent, 1 gen child, 2 gen child, ...])
func getTreePids(rootPid uint32) ([]uint32, error) {
	// https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
	procEntry := syscall.ProcessEntry32{}
	parentLayer := []uint32{rootPid}
	treePids := parentLayer
	foundRootPid := false

	snapshot, err := syscall.CreateToolhelp32Snapshot(uint32(syscall.TH32CS_SNAPPROCESS), 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snapshot)

	procEntry.Size = uint32(unsafe.Sizeof(procEntry))

	for {
		// set procEntry to the first process in the snapshot
		err = syscall.Process32First(snapshot, &procEntry)
		if err != nil {
			return nil, err
		}

		// loop through the processes in the snapshot, if the parent pid of the analyzed process
		// is in in the parent layer, append the analyzed process pid in the child layer
		var childLayer []uint32
		for {
			if procEntry.ProcessID == rootPid {
				foundRootPid = true
			}

			if contains(parentLayer, procEntry.ParentProcessID) {
				// avoid adding a pid if it's already contained in treePids
				// useful for pid 0 whose ppid is 0 and would lead to recursion (windows)
				if !contains(treePids, procEntry.ProcessID) {
					childLayer = append(childLayer, procEntry.ProcessID)
				}
			}

			// advance to next process in snapshot
			err = syscall.Process32Next(snapshot, &procEntry)
			if err != nil {
				// if there aren't anymore processes to be analyzed, break out of the loop
				break
			}
		}

		// if the specified rootPid is not found, return error
		if !foundRootPid {
			return nil, fmt.Errorf("specified rootPid not found")
		}

		// fmt.Println(childLayer)

		// there are no more child processes, return the process tree
		if len(childLayer) == 0 {
			return treePids, nil
		}

		// append the child layer to the tree pids
		treePids = append(treePids, childLayer...)

		// to analyze the next layer, set the child layer to be the new parent layer
		parentLayer = childLayer
	}
}

func contains(list []uint32, e uint32) bool {
	for _, l := range list {
		if l == e {
			return true
		}
	}
	return false
}

func allDone(ppid int) (err error) {
	log.Println("allDone", ppid)
	pids, err := getTreePids(uint32(ppid))
	slices.Reverse(pids)
	if err == nil {
		for _, pid := range pids {
			Process, err := os.FindProcess(int(pid))
			if err == nil {
				err = Process.Kill()
				if err == nil {
					log.Println("pid", pid, "done")
				}
			}
		}
		return
	}
	return pDone(ppid)
}

func UnloadEmbedded(src, root, trg string) error {
	srcLen := len(strings.Split(src, "/"))
	dirs := append([]string{root}, strings.Split(trg, `\`)...)
	return fs.WalkDir(fs.FS(bin), src, func(unix string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		win := filepath.Join(append(dirs, strings.Split(unix, "/")[srcLen:]...)...)
		if d.IsDir() {
			_, err = os.Stat(win)
			if err != nil {
				err = os.MkdirAll(win, 0666)
			}
			return err
		}
		bytes, err := bin.ReadFile(unix)
		if err != nil {
			return err
		}
		var size int64
		fi, err := os.Stat(win)
		if err == nil {
			size = fi.Size()
			if int64(len(bytes)) == size {
				return nil
			}
		}
		log.Println(win, len(bytes), "->", size)
		return os.WriteFile(win, bytes, 0666)
	})
}
