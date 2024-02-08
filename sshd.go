package main

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/abakum/go-ansiterm"
	"github.com/abakum/go-console"
	"github.com/abakum/go-netstat/netstat"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"github.com/xlab/closer"
	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
	nog "golang.ngrok.com/ngrok/log"
	"golang.org/x/crypto/ssh"
)

func server() {
	ctxRWE, caRW := context.WithCancel(context.Background())
	defer caRW()
	VisitAll(fmt.Sprintf("%s@%s", un(""), Hp))

	for i, rfc2217 := range T {
		if len(C) > i {
			com(parseHPHP(rfc2217, RFC2217), C[i])
		}
	}

	// if sshd of OpenSSH use listenaddress==hp then use it else start nfrokSSH daemon
	// если sshd от OpenSSH использует listenaddress==hp то он будет использоваться в противном случае запустится сервер nfrokSSH
	listenaddress, sshdExe := la(SSHD, 22)
	if listenaddress != "" {
		go established(ctxRWE, sshdExe)
	}
	if listenaddress == Hp || Hp == "0.0.0.0:22" {
		Once.Do(func() {
			var (
				exe string
				err error
				ExeInfo,
				SymlinkInfo fs.FileInfo
				src,
				dst *os.File
				written int64
			)
			if !HardExe { // copy
				ExeInfo, err = os.Stat(Exe)
				if err != nil {
					Println(Exe, err)
					return
				}
				src, err = os.Open(Exe)
				if err != nil {
					Println(Exe, err)
					return
				}
				defer src.Close()

			}
			for _, dir := range filepath.SplitList(os.Getenv("Path")) {
				if !HardPath(Drives, dir) {
					continue
				}
				Symlink := filepath.Join(dir, Image)
				if HardExe {
					Println("os.Symlink", Exe, Symlink)
					exe, err = os.Readlink(Symlink)
					if os.IsNotExist(err) {
						err = os.Symlink(Exe, Symlink)
					} else {
						err = nil
						if exe != Exe {
							err = os.Remove(Symlink)
							if err == nil {
								err = os.Symlink(Exe, Symlink)
							}
						}
					}
				} else {
					Println("io.Copy", Symlink, Exe)
					SymlinkInfo, err = os.Stat(Symlink)
					if !(err == nil && ExeInfo.Size() == SymlinkInfo.Size()) {
						dst, err = os.Create(Symlink)
						if err != nil {
							Println(Symlink, err)
							continue
						}
						defer dst.Close()
						written, err = io.Copy(dst, src)
						if err != nil || written != ExeInfo.Size() {
							dst.Close()
							Println(Symlink, err)
							continue
						}
					}
				}
				Println(Symlink, err)
				if err == nil {
					return
				}
			}
		})
	}
	if listenaddress == Hp {
		// to prevent disconnect by idle set `ClientAliveInterval 100`
		li.Printf("%s daemon waiting on - %s сервер ожидает на %s\n", sshdExe, sshdExe, Hp)
		if NgrokHasTunnel || !NgrokOnline {
			li.Printf("LAN mode of %s daemon  - Локальный режим %s сервера\n", sshdExe, sshdExe)
			li.Println("to connect use - чтоб подключится используй", use(Hp))

			watch(ctxRWE, caRW, Hp) // local
			Println("watch done")
		} else {
			li.Printf("Ngrok mode of %s daemon  - Ngrok режим %s сервера\n", sshdExe, sshdExe)
			li.Printf("to connect use - чтоб подключится используй `%s`", Image)

			go established(ctxRWE, Image)
			Println("run done", run(ctxRWE, caRW, Hp, false)) // create tunnel
		}
		return
	}

	ForwardedTCPHandler := &gl.ForwardedTCPHandler{}

	server := gl.Server{
		Addr: Hp,
		// next for ssh -R host:port:x:x
		ReversePortForwardingCallback: gl.ReversePortForwardingCallback(func(ctx gl.Context, host string, port uint32) bool {
			li.Println("Attempt to bind - Начать слушать", host, port, "granted - позволено")
			return true
		}),
		RequestHandlers: map[string]gl.RequestHandler{
			"tcpip-forward":        ForwardedTCPHandler.HandleSSHRequest, // to allow remote forwarding
			"cancel-tcpip-forward": ForwardedTCPHandler.HandleSSHRequest, // to allow remote forwarding
		},
		// before for ssh ssh -R host:port:x:x

		// next for ssh -L x:dhost:dport
		LocalPortForwardingCallback: gl.LocalPortForwardingCallback(func(ctx gl.Context, dhost string, dport uint32) bool {
			li.Println("Accepted forward - Разрешен перенос", dhost, dport)
			return true
		}),
		ChannelHandlers: map[string]gl.ChannelHandler{
			"session":      winssh.SessionHandler, // to allow agent forwarding
			"direct-tcpip": gl.DirectTCPIPHandler, // to allow local forwarding
		},
		// before for ssh -L x:dhost:dport

		SubsystemHandlers: map[string]gl.SubsystemHandler{
			"sftp":                  winssh.SubsystemHandlerSftp,  // to allow sftp
			winssh.AgentRequestType: winssh.SubsystemHandlerAgent, // to allow agent forwarding
		},
		SessionRequestCallback: SessionRequestCallback,
		// IdleTimeout:            -time.Second * 100, // send `keepalive` every 100 seconds
		// MaxTimeout:             -time.Second * 300, // сlosing the session after 300 seconds with no response
		Version: Imag + "_" + Ver,
	}

	// next for server key
	server.AddHostKey(Signer)
	// before for server key

	// next for client keys
	publicKeyOption := gl.PublicKeyAuth(func(ctx gl.Context, key gl.PublicKey) bool {
		Println("User", ctx.User(), "from", ctx.RemoteAddr())
		Println("key", FingerprintSHA256(key))

		AuthorizedKeys = KeyFromClient(key, AuthorizedKeys) //from first user
		return Authorized(key, AuthorizedKeys)
	})

	server.SetOption(publicKeyOption)
	// before for client keys

	gl.Handle(func(s gl.Session) {
		defer s.Exit(0)
		switch 1 {
		case 1:
			if len(s.Command()) > 1 {
				base := filepath.Base(s.Command()[0])
				bas := strings.Split(base, ".")[0]
				if strings.EqualFold(bas, Imag) {
					ret, res := rtv(s.Command()[1])
					if ret {
						if res == CGIR {
							caRW()
						} else {
							fmt.Fprint(s, res)
						}
						return
					}
				}
			}
		}
		ShellOrExec(s)
	})

	li.Printf("%s daemon waiting on - %s сервер ожидает на %s\n", Image, Image, Hp)

	go func() {
		if NgrokHasTunnel || !NgrokOnline {
			li.Printf("LAN mode of %s daemon - Локальный режим %s сервера\n", Image, Image)
			li.Println("to connect use - чтоб подключится используй", use(Hp))

			watch(ctxRWE, caRW, Hp) // local
			ltf.Println("local done")
		} else {
			li.Printf("Ngrok mode of %s daemon  - Ngrok режим %s сервера\n", Image, Image)
			li.Printf("to connect use - чтоб подключится используй `%s`\n", Image)

			run(ctxRWE, caRW, Hp, false) //create tunnel
			ltf.Println("ngrok done")
		}
		server.Close()
	}()
	go established(ctxRWE, Image)
	Println("ListenAndServe", server.ListenAndServe())
}

func un(ru string) (u string) {
	u = Ln
	if u == "" {
		u = ru
	}
	if u == "" {
		u = os.Getenv("USERNAME")
	}
	return
}

func use(hp string) (s string) {
	h, p, _ := net.SplitHostPort(hp)
	if p == PORT {
		p = ""
	}
	if h != ALL {
		return fmt.Sprintf("`%s`", strings.Trim(Image+" "+un("")+"@"+net.JoinHostPort(h, p), " :"))
	}
	s = ""
	for _, h := range Ips {
		s += fmt.Sprintf("\n\t`%s`", strings.Trim(Image+" "+un("")+"@"+net.JoinHostPort(h, p), " :"))
	}
	return
}

// for `ssh :`
func withMetadata(lPort string) (meta string) {
	h, p := SplitHostPort(lPort, "", PORT)
	if h == ALL {
		h = strings.Join(Ips, ",")
	}
	return fmt.Sprintf("%s@%s:%s", un(""), h, p)
}

func run(ctx context.Context, ca context.CancelFunc, dest string, http bool) error {
	if true {
		ctxWT, caWT := context.WithTimeout(ctx, time.Second)
		defer caWT()
		sess, err := ngrok.Connect(ctxWT,
			ngrok.WithAuthtoken(NgrokAuthToken),
		)
		if err != nil {
			return Errorf("Connect %w", err)
		}
		sess.Close()
		caWT()
	}

	// ctx, ca := context.WithCancel(ctx)
	// defer func() {
	// 	if err != nil {
	// 		ca()
	// 	}
	// }()

	endpoint := config.TCPEndpoint(config.WithMetadata(withMetadata(dest)))
	if http {
		endpoint = config.HTTPEndpoint(config.WithMetadata(withMetadata(dest)))
	}
	destURL, err := url.Parse("tcp://" + dest)
	if err != nil {
		return Errorf("Parse %w", err)
	}
	fwd, err := ngrok.ListenAndForward(ctx,
		destURL,
		endpoint,
		ngrok.WithAuthtoken(NgrokAuthToken),
		ngrok.WithStopHandler(func(ctx context.Context, sess ngrok.Session) error {
			defer closer.Close()
			Println("StopHandler - Получена команда остановиться")
			ca()
			return nil
		}),
		ngrok.WithRestartHandler(func(ctx context.Context, sess ngrok.Session) error {
			ltf.Println("RestartHandler - Получена команда перезапуститься")
			ca()
			return nil
		}),
		ngrok.WithDisconnectHandler(func(ctx context.Context, sess ngrok.Session, err error) {
			Println("DisconnectHandler - Обнаружено отключение", err)
			ca()
		}),
		ngrok.WithLogger(&logger{lvl: nog.LogLevelDebug}),
	)
	if err != nil {
		return srcError(err)
	}

	ltf.Println("ngrok tunnel created - создан туннель", fwd.URL(), fwd.Metadata())
	go watch(ctx, ca, dest)

	return srcError(fwd.Wait())
}

// call ca() and return on `Service has been discontinued`
func watch(ctx context.Context, ca context.CancelFunc, dest string) {
	if strings.HasPrefix(dest, ":") {
		dest = ALL + dest
	}
	old := -1
	ste_ := ""
	t := time.NewTicker(TOW)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			ste := ""
			new := netSt(func(s *netstat.SockTabEntry) bool {
				ok := s.State == netstat.Listen && s.LocalAddr.String() == dest
				if ok {
					ste += fmt.Sprintln("\t", s.LocalAddr, s.State)
				}
				return ok
			})
			if new == 0 {
				lt.Print("The service has been stopped - Служба остановлена\n\t", dest)
				if ca != nil {
					ca()
				}
				return
			}
			if old != new {
				if new > old {
					lt.Print("The service is running - Служба работает\n", ste)
				}
				ste_ = ste
				old = new
			}
			if ste_ != ste {
				lt.Print("The service has been changed - Служба сменилась\n", ste)
				ste_ = ste
			}
		case <-ctx.Done():
			Println("watch", dest, "done")
			return
		}
	}
}

func established(ctx context.Context, imagename string) {
	old := 0
	ste_ := ""
	t := time.NewTicker(TOW)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			ste := ""
			new := netSt(func(s *netstat.SockTabEntry) bool {
				ok := s.Process != nil && s.Process.Name == imagename && s.State == netstat.Established
				if ok {
					ste += fmt.Sprintln("\t", s.LocalAddr, s.RemoteAddr, s.State)
				}
				return ok
			})
			if old != new {
				switch {
				case new == 0:
					lt.Println(imagename, "There are no connections - Нет подключений")
				case old > new:
					lt.Print(imagename, " Connections have decreased - Подключений уменьшилось\n", ste)
				default:
					lt.Print(imagename, " Connections have increased - Подключений увеличилось\n", ste)
				}
				ste_ = ste
				old = new
			}
			if ste_ != ste {
				lt.Print(imagename, " Сonnections have changed - Подключения изменились\n", ste)
				ste_ = ste
			}
		case <-ctx.Done():
			Println("established", imagename, "done")
			return
		}
	}
}

// func(s *netstat.SockTabEntry) bool {return s.State == a}
func netSt(accept netstat.AcceptFn) int {
	tabs, err := netstat.TCPSocks(accept)
	if err != nil {
		return 0
	}
	return len(tabs)
}

// Simple logger that forwards to the Go standard logger.
type logger struct {
	lvl nog.LogLevel
}

func (l *logger) Log(ctx context.Context, lvl nog.LogLevel, msg string, data map[string]interface{}) {
	if lvl > l.lvl {
		return
	}
	// lvlName, _ := ngrok_log.StringFromLogLevel(lvl)
	// log.Printf("[%s] %s %v", lvlName, msg, data)
	if msg != "heartbeat received" {
		ltf.Println(msg, data)
	}
}

// logging sessions
func SessionRequestCallback(s gl.Session, requestType string) bool {
	if s == nil {
		return false
	}
	log.Println(s.RemoteAddr(), requestType, s.Command())
	return true
}

func la(xExe string, port uint16) (listenaddress string, exe string) {
	exe = xExe
	tabs, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
		if s.State != netstat.Listen {
			return false
		}
		if s.Process != nil {
			if s.Process.Name == Image {
				if strconv.Itoa(int(port)) == PORT {
					ltf.Printf("%s listen on %s\n", Image, s.LocalAddr.String())
				}
				return false
			}
			if s.Process.Name == xExe {
				return true
			}
			if s.LocalAddr.Port == port {
				exe = s.Process.Name
				return true
			}
			return false
		} else {
			return s.LocalAddr.Port == port
		}
	})
	if err != nil {
		return
	}
	for _, s := range tabs {
		listenaddress = s.LocalAddr.String()
		return
	}
	return
}

func isListen(host string, port int, pid int) (ok bool) {
	up := uint16(port)
	tabs, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
		return s.State == netstat.Listen && (host == "" || host == s.LocalAddr.IP.String()) && (s.LocalAddr.Port == up || s.Process != nil && s.Process.Pid == pid)
	})
	return err == nil && len(tabs) > 0
}

// is autorized
func Authorized(key gl.PublicKey, authorized []ssh.PublicKey) bool {
	for _, k := range authorized {
		if gl.KeysEqual(key, k) {
			return true
		}
	}
	return false
}

// case no files and not embed then write from first client
func KeyFromClient(key gl.PublicKey, old []ssh.PublicKey) []ssh.PublicKey {
	if len(old) > 0 {
		return old
	}
	// only first login
	ltf.Println("KeyFromClient", FingerprintSHA256(key))
	Println("WriteFile", AuthorizedKeysIni, os.WriteFile(AuthorizedKeysIni, ssh.MarshalAuthorizedKey(key), FiLEMODE))
	return []ssh.PublicKey{key}
}

// for shell and exec
func ShellOrExec(s gl.Session) {
	RemoteAddr := s.RemoteAddr()
	defer ltf.Println(RemoteAddr, "done")

	ptyReq, winCh, isPty := s.Pty()
	if !isPty {
		winssh.NoPTY(s)
		return
	}
	// ssh -p 2222 a@127.0.0.1
	// ssh -p 2222 a@127.0.0.1 -t commands
	stdout, err := console.New(ptyReq.Window.Width, ptyReq.Window.Width)
	if err != nil {
		letf.Println("unable to create console", err)
		winssh.NoPTY(s)
		return
	}
	args := winssh.ShArgs(s.Command())
	defer func() {
		ltf.Println(args, "done")
		if stdout != nil {
			// stdout.Close()
			stdout.Kill()
		}
	}()
	stdout.SetCWD(winssh.Home(s))
	stdout.SetENV(winssh.Env(s, args[0]))
	err = stdout.Start(args)
	if err != nil {
		letf.Println("unable to start", args, err)
		winssh.NoPTY(s)
		return
	}

	ppid, _ := stdout.Pid()
	ltf.Println(args, ppid)
	go func() {
		for {
			if stdout == nil || s == nil {
				return
			}
			select {
			case <-s.Context().Done():
				stdout.Close()
				return
			case win := <-winCh:
				ltf.Println("PTY SetSize", win)
				if win.Height == 0 && win.Width == 0 {
					stdout.Close()
					return
				}
				if err := stdout.SetSize(win.Width, win.Height); err != nil {
					letf.Println(err)
				}
			}
		}
	}()

	time.AfterFunc(time.Millisecond*100, func() {
		fmt.Fprintf(s, "%c]0;%s%c", ansiterm.ANSI_ESCAPE_PRIMARY, s.Context().ServerVersion(), ansiterm.ANSI_BEL)
	})
	go io.Copy(stdout, s)
	io.Copy(s, stdout)
}
