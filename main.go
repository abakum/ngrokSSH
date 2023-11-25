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
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"

	"github.com/abakum/go-console"
	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	"github.com/xlab/closer"
	gossh "golang.org/x/crypto/ssh"
)

const (
	sshHostKey                   = "ssh_host_rsa_key"               // OpenSSH for Windows
	administratorsAuthorizedKeys = "administrators_authorized_keys" // OpenSSH for Windows
	authorizedKeys               = "authorized_keys"                // write from embed or from first client
	// Addr                         = "127.0.0.1:22"
	Addr          = ":2222"
	BIN           = "OpenSSH"
	SSH_AUTH_SOCK = "SSH_AUTH_SOCK="
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
	if s == nil {
		return false
	}
	ptyReq, _, isPty := s.Pty()
	pr := ""
	if isPty {
		pr = fmt.Sprintf("%v", ptyReq)
	}
	log.Println(s.RemoteAddr(), requestType, s.Command(), pr)
	return true
}

// SubsystemHandlerSftp for sftp
func SubsystemHandlerSftp(s ssh.Session) {
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
	defer closer.Close()
	closer.Bind(func() {
		allDone(os.Getpid())
	})

	UnloadEmbedded(path.Join(BIN, runtime.GOARCH), os.Getenv("ProgramFiles"), BIN)
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
			"session":      SessionHandler,
			"direct-tcpip": ssh.DirectTCPIPHandler,
		},
		// before for ssh -L x:dhost:dport

		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp":           SubsystemHandlerSftp,
			agentRequestType: SubsystemHandlerAgent, //fake Subsystem
		},
		SessionRequestCallback: SessionRequestCallback,
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
		return
	}

	// next for server key
	pri := hKey(cwd, sshHostKey)
	pemBytes, err := os.ReadFile(pri)
	if err != nil {
		key, err = generateSigner(pri)
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
	for _, akf := range aKeys() {
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
		shellOrExec(s)
	})

	log.Println("starting ssh server on", sshd.Addr)
	log.Fatal(sshd.ListenAndServe())

}

// like ssh.generateSigner plus write key to files
func generateSigner(pri string) (ssh.Signer, error) {
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

		os.WriteFile(pri+".pub", data, 0644)
	}

	return gossh.NewSignerFromKey(key)
}

// for not PTY as `klink a@:2222 -T` or `klink a@:2222 commands` or `kitty_portable a@:2222 -T`
func noPTY(s ssh.Session) {
	shell := len(s.Command()) == 0
	args := shArgs(s.Command())
	e := env(s, args[0])
	args = shellArgs(args)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Dir = cwd
	cmd.Env = append(os.Environ(), e...)

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
	ppid := cmd.Process.Pid
	log.Println(args, ppid)

	done := s.Context().Done()
	go func() {
		<-done
		if shell {
			fmt.Fprint(stdin, "exit\n")
			stdin.Close()
			// allDone(ppid) //force
		}
		log.Println(args, "done")
	}()

	go io.Copy(stdin, s)
	io.Copy(s, stdout)
	err = cmd.Wait()
	if err != nil {
		log.Println(args[0], err)
	}
}

// for shell and exec
func shellOrExec(s ssh.Session) {
	shell := len(s.Command()) == 0
	RemoteAddr := s.RemoteAddr()
	defer func() {
		log.Println(RemoteAddr, "done")
		if s != nil {
			s.Close()
		}
	}()

	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		noPTY(s)
		return
	}
	// for `kitty_portable a@:2222` or `klink a@:2222` or `klink a@:2222 -t commands`
	stdin, err := console.New(ptyReq.Window.Width, ptyReq.Window.Width)
	if err != nil {
		fmt.Fprint(s, "unable to create console", err)
		noPTY(s) // fallback
		return
	}
	args := shArgs(s.Command())
	stdin.SetENV(env(s, args[0]))
	defer func() {
		log.Println(args, "done")
		if stdin != nil {
			stdin.Close()
		}
	}()

	err = stdin.Start(args)
	if err != nil {
		fmt.Fprint(s, "unable to start", args, err)
		noPTY(s) // fallback
		return
	}
	log.Println(args)

	done := s.Context().Done()
	go func() {
		for {
			select {
			case <-done:
				if shell {
					fmt.Fprint(stdin, "exit\n")
					stdin.Close()
				}
				return
			case win := <-winCh:
				log.Println("PTY SetSize", win)
				if stdin == nil {
					return
				}
				if win.Height == 0 && win.Width == 0 {
					stdin.Close()
					return
				}
				if err := stdin.SetSize(win.Width, win.Height); err != nil {
					log.Println(err)
				}
			}
		}
	}()

	go io.Copy(stdin, s)
	io.Copy(s, stdin)
	if _, err := stdin.Wait(); err != nil {
		log.Println(args, err)
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

// parent done
func pDone(ppid int) (err error) {
	Process, err := os.FindProcess(ppid)
	if err == nil {
		err = Process.Kill()
		if err == nil {
			log.Println("ppid", ppid, "done")
		}
	}
	return
}

// named pipe for Windows or unix sock
func pipe(sess *session) {
	s := ""
	if runtime.GOOS == "windows" {
		s = fmt.Sprintf(`%s%s\%s`, PIPE, sess.LocalAddr(), sess.RemoteAddr())
	} else {
		dir, err := os.MkdirTemp("", agentTempDir)
		if err != nil {
			dir = os.TempDir()
		}
		s = path.Join(dir, agentListenFile)
	}
	e := append(sess.env, SSH_AUTH_SOCK+s)
	sess.env = e
}

// callback for agentRequest
func (sess *session) handleRequests(reqs <-chan *gossh.Request) {
	for req := range reqs {
		switch req.Type {
		case "shell", "exec":
			if sess.handled {
				req.Reply(false, nil)
				continue
			}

			var payload = struct{ Value string }{}
			gossh.Unmarshal(req.Payload, &payload)
			sess.rawCmd = payload.Value

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				req.Reply(false, nil)
				continue
			}

			sess.handled = true
			req.Reply(true, nil)

			go func() {
				sess.handler(sess)
				sess.Exit(0)
			}()
		case "subsystem":
			if sess.handled {
				req.Reply(false, nil)
				continue
			}

			var payload = struct{ Value string }{}
			gossh.Unmarshal(req.Payload, &payload)

			sess.subsystem = payload.Value

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				sess.rawCmd = ""
				req.Reply(false, nil)
				continue
			}

			handler := sess.subsystemHandlers[payload.Value]
			if handler == nil {
				handler = sess.subsystemHandlers["default"]
			}
			if handler == nil {
				req.Reply(false, nil)
				continue
			}

			sess.handled = true
			req.Reply(true, nil)

			go func() {
				handler(sess)
				sess.Exit(0)
			}()
		case "env":
			if sess.handled {
				req.Reply(false, nil)
				continue
			}
			var kv struct{ Key, Value string }
			gossh.Unmarshal(req.Payload, &kv)
			sess.env = append(sess.env, fmt.Sprintf("%s=%s", kv.Key, kv.Value))
			req.Reply(true, nil)
		case "signal":
			var payload struct{ Signal string }
			gossh.Unmarshal(req.Payload, &payload)
			sess.Lock()
			if sess.sigCh != nil {
				sess.sigCh <- ssh.Signal(payload.Signal)
			} else {
				if len(sess.sigBuf) < maxSigBufSize {
					sess.sigBuf = append(sess.sigBuf, ssh.Signal(payload.Signal))
				}
			}
			sess.Unlock()
		case "pty-req":
			if sess.handled || sess.pty != nil {
				req.Reply(false, nil)
				continue
			}
			ptyReq, ok := parsePtyRequest(req.Payload)
			if !ok {
				req.Reply(false, nil)
				continue
			}
			if sess.ptyCb != nil {
				ok := sess.ptyCb(sess.ctx, ptyReq)
				if !ok {
					req.Reply(false, nil)
					continue
				}
			}
			sess.pty = &ptyReq
			sess.winch = make(chan ssh.Window, 1)
			sess.winch <- ptyReq.Window
			defer func() {
				// when reqs is closed
				close(sess.winch)
			}()
			req.Reply(ok, nil)
		case "window-change":
			if sess.pty == nil {
				req.Reply(false, nil)
				continue
			}
			win, ok := parseWinchRequest(req.Payload)
			if ok {
				sess.pty.Window = win
				sess.winch <- win
			}
			req.Reply(ok, nil)
		case agentRequestType:
			// TODO: option/callback to allow agent forwarding
			if sess.agent {
				req.Reply(false, nil)
				continue
			}

			// If there's a session policy callback, we need to confirm before
			// accepting the session.
			if sess.sessReqCb != nil && !sess.sessReqCb(sess, req.Type) {
				req.Reply(false, nil)
				continue
			}

			handler := sess.subsystemHandlers[agentRequestType]
			if handler == nil {
				req.Reply(false, nil)
				continue
			}

			pipe(sess)

			sess.agent = true
			req.Reply(true, nil)

			go func() {
				handler(sess)
				sess.agent = false
			}()
			// ssh.SetAgentRequested(sess.ctx)
			// req.Reply(true, nil)
		case "break":
			ok := false
			sess.Lock()
			if sess.breakCh != nil {
				sess.breakCh <- true
				ok = true
			}
			req.Reply(ok, nil)
			sess.Unlock()
		default:
			// TODO: debug log
			req.Reply(false, nil)
		}
	}
}

func doner(l net.Listener, s ssh.Session) {
	<-s.Context().Done()
	log.Println(l.Addr().String(), "done")
	l.Close()
}
