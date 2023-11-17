/*
git clone https://github.com/abakum/ngrokSSH
go mod init github.com/abakum/ngrokSSH
go get github.com/gliderlabs/ssh
go get github.com/pkg/sftp
// go get github.com/runletapp/go-console
// go get github.com/jm33-m0/go-console
go get github.com/abakum/go-console
go mod tidy
*/
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed" //no lint
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/abakum/go-console"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"
)

const (
	sshHostKey                   = "ssh_host_rsa_key"               // OpenSSH for Windows
	administratorsAuthorizedKeys = "administrators_authorized_keys" // OpenSSH for Windows
	authorizedKeys               = "authorized_keys"                // stored from embed
	Addr                         = ":2222"
)

var (
	//go:embed authorized_keys
	authorized_keys []byte

	key     ssh.Signer
	allowed []ssh.PublicKey
	cwd     string
)

// logging sessions
func SessionRequestCallback(s ssh.Session, requestType string) bool {
	log.Println(s.RemoteAddr(), requestType)
	return true
}

// SubsystemHandlers for sftp
func SubsystemHandlers(s ssh.Session) {
	debugStream := io.Discard
	serverOptions := []sftp.ServerOption{
		sftp.WithDebug(debugStream),
	}
	server, err := sftp.NewServer(
		s,
		serverOptions...,
	)
	if err != nil {
		log.Printf("sftp server init error: %s\n", err)
		return
	}
	if err := server.Serve(); err == io.EOF {
		server.Close()
		fmt.Println("sftp client exited session.")
	} else if err != nil {
		fmt.Println("sftp server completed with error:", err)
	}
}

func main() {
	ForwardedTCPHandler := &ssh.ForwardedTCPHandler{}

	sshd := ssh.Server{
		Addr: Addr,
		// next for ssh -R host:port:x:x
		ReversePortForwardingCallback: ssh.ReversePortForwardingCallback(func(ctx ssh.Context, host string, port uint32) bool {
			log.Println("attempt to bind", host, port, "granted")
			return true
		}),
		RequestHandlers: map[string]ssh.RequestHandler{
			"tcpip-forward":        ForwardedTCPHandler.HandleSSHRequest,
			"cancel-tcpip-forward": ForwardedTCPHandler.HandleSSHRequest,
		},
		// before for ssh ssh -R host:port:x:x

		// next for ssh -L x:dhost:dport
		LocalPortForwardingCallback: ssh.LocalPortForwardingCallback(func(ctx ssh.Context, dhost string, dport uint32) bool {
			log.Println("accepted forward", dhost, dport)
			return true
		}),
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session":      ssh.DefaultSessionHandler,
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
		// before for ssh -L x:dhost:dport

		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": SubsystemHandlers,
		},
		SessionRequestCallback: SessionRequestCallback,
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
		return
	}

	// next for server key
	pri := filepath.Join(cwd, sshHostKey)
	pub := filepath.Join(cwd, sshHostKey+".pub")
	pemBytes, err := os.ReadFile(pri)
	if err != nil {
		key, err = generateSigner(pri, pub)
	} else {
		key, err = gossh.ParsePrivateKey(pemBytes)
	}
	if err != nil {
		log.Fatal(err)
		return
	}

	sshd.AddHostKey(key)
	if len(sshd.HostSigners) < 1 {
		log.Fatal("host key was not properly added")
		return
	}
	// before for server key

	// next for client keys
	for _, akf := range []string{
		filepath.Join(os.Getenv("AllUserProfile"), administratorsAuthorizedKeys),
		filepath.Join(os.Getenv("UserProfile"), ".ssh", authorizedKeys),
		filepath.Join(cwd, authorizedKeys),
	} {
		kk := fileToAllowed(os.ReadFile(akf))
		allowed = append(allowed, kk...)
	}

	bytesToAllowed(authorized_keys)

	publicKeyOption := ssh.PublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
		keyToAllowed(key)
		for _, k := range allowed {
			if ssh.KeysEqual(key, k) {
				return true
			}
		}
		return false
	})

	sshd.SetOption(publicKeyOption)
	// before for client keys

	ssh.Handle(func(s ssh.Session) {
		log.Println("user", s.User())
		if s.PublicKey() != nil {
			authorizedKey := gossh.MarshalAuthorizedKey(s.PublicKey())
			log.Println("used public key", string(authorizedKey))
		}
		cmdPTY(s)
	})

	log.Println("starting ssh server on", sshd.Addr)
	log.Fatal(sshd.ListenAndServe())
}

// like ssh.generateSigner plus write key to files
func generateSigner(pri, pub string) (ssh.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	Bytes := x509.MarshalPKCS1PrivateKey(key)
	data := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: Bytes,
	})
	os.WriteFile(pri, data, 0644)

	Bytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err == nil {
		data := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: Bytes,
		})

		os.WriteFile(pub, data, 0644)
	}

	return gossh.NewSignerFromKey(key)
}

func psArgs(commands []string) (args []string) {
	args = []string{"powershell", "-NoProfile", "-NoLogo"}
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

// for not PTY as klink a@:2222 -T or klink a@:2222 dir
func powerShell(s ssh.Session) { // reqs <-chan *gossh.Request
	args := psArgs(s.Command())
	cmd := exec.Command(args[0], args[1:]...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0 +
			// syscall.STARTF_USESTDHANDLES +
			0}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprint(s, "unable to open stdout pipe", err)
		return
	}

	cmd.Stderr = cmd.Stdout

	stdin, err := cmd.StdinPipe()
	if err != nil {
		fmt.Fprint(s, "unable to open stdin pipe", err)
		return
	}

	err = cmd.Start()
	if err != nil {
		fmt.Fprint(s, "could not start", args, err)
		return
	}
	log.Println(args)

	// go gossh.DiscardRequests(reqs)
	go func() {
		buf := make([]byte, 128)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("stdout.Read %s", err)
				}
				return
			}

			_, err = s.Write(buf[:n])
			if err != nil {
				log.Printf("s.Write %s", err)
				return
			}
		}
	}()

	go func() {
		buf := make([]byte, 128)
		for {
			n, err := s.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Printf("s.Read %s", err)
				}
				return
			}

			_, err = stdin.Write(buf[:n])
			if err != nil {
				if err != io.EOF {
					log.Printf("stdin.Write %s", err)
				}
				return
			}

		}
	}()

	done := s.Context().Done()
	go func() {
		<-done
		log.Println(args, "done")
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
	err = cmd.Wait()
	if err != nil {
		log.Println(args[0], err)
	}
}

func cmdArgs(commands []string) (args []string) {
	const SH = "cmd.exe"
	path := ""
	var err error
	for _, shell := range []string{os.Getenv("ComSpec"), SH} {
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

// for shell and exec
func cmdPTY(s ssh.Session) {
	RemoteAddr := s.RemoteAddr()
	defer func() {
		log.Println(RemoteAddr, "done")
		if s != nil {
			s.Close()
		}
	}()

	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		powerShell(s)
	} else {
		// for kitty_portable a@:2222
		f, err := console.New(ptyReq.Window.Width, ptyReq.Window.Width)

		if err != nil {
			fmt.Fprint(s, "unable to create console", err)
			return
		}
		args := []string{}
		if runtime.GOOS == "windows" {
			args = cmdArgs(s.Command())
			// f.SetENV([]string{"TERM=dumb", "NO_COLOR=yes"})
		} else {
			args = shArgs(s.Command())
			f.SetENV([]string{"TERM=" + ptyReq.Term})
		}

		defer func() {
			log.Println(args, "done")
			if f != nil {
				f.Close()
			}
		}()

		err = f.Start(args)
		if err != nil {
			fmt.Fprint(s, "unable to start", args, err)
			return
		}
		log.Println(args)

		done := s.Context().Done()
		go func() {
			for {
				select {
				case <-done:
					f.Close()
					return
				case win := <-winCh:
					f.SetSize(win.Width, win.Height)
				}
			}
		}()

		go func() {
			io.Copy(f, s) // stdin
		}()
		io.Copy(s, f) // stdout

		if _, err := f.Wait(); err != nil {
			log.Println(args[0], err)
		}
	}
}

// ParseAuthorizedKeys
func fileToAllowed(bs []byte, err error) (allowed []ssh.PublicKey) {
	if err != nil {
		return
	}
	for _, b := range bytes.Split(bs, []byte("\n")) {
		k, _, _, _, err := ssh.ParseAuthorizedKey(b)
		if err == nil {
			log.Println("fileToAllowed", string(b))
			allowed = append(allowed, k)
		}
	}
	return
}

// case no files then write from embed
func bytesToAllowed(authorized_keys []byte) {
	if len(allowed) > 0 || len(authorized_keys) == 0 {
		return
	}
	allowed = fileToAllowed(authorized_keys, nil)
	if len(allowed) > 0 {
		log.Println("bytesToAllowed", string(authorized_keys))
		os.WriteFile(filepath.Join(cwd, authorizedKeys), authorized_keys, 0644)
	}
}

// case no files and not embed then write from first client
func keyToAllowed(key ssh.PublicKey) {
	if len(allowed) > 0 {
		return
	}
	b := gossh.MarshalAuthorizedKey(key)
	log.Println("keyToAllowed", string(b))
	bytesToAllowed(b)
}
