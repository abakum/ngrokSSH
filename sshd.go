package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/abakum/go-netstat/netstat"
	"github.com/abakum/winssh"
	gl "github.com/gliderlabs/ssh"
	"github.com/xlab/closer"
	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
	nog "golang.ngrok.com/ngrok/log"
	"golang.org/x/crypto/ssh"
)

const (
	TOS = time.Second * 7
)

func server() {
	const (
		SSHD = "sshd.exe"
	)
	VisitAll(fmt.Sprintf("%s@%s", un(""), Hp))

	for i, rfc2217 := range T {
		if len(C) > i {
			com(parseHPHP(rfc2217, RFC2217), C[i])
		}
	}

	go established(Image)

	// if sshd of OpenSSH use listenaddress==hp then use it else start nfrokSSH daemon
	// если sshd от OpenSSH использует listenaddress==hp то он будет использоваться в противном случае запустится сервер nfrokSSH
	for {
		listenaddress, sshdExe := la(SSHD, 22)
		if listenaddress != Hp {
			break
		}
		// to prevent disconnect by idle set `ClientAliveInterval 100`
		li.Printf("%s daemon waiting on - %s сервер ожидает на %s\n", sshdExe, sshdExe, Hp)
		if NgrokSSHD || !NgrokOnline {
			li.Printf("local mode of %s daemon  - локальный режим %s сервера\n", sshdExe, sshdExe)
			li.Println("to connect use - чтоб подключится используй", use(Hp))
			watch(Hp, false) // local
			ltf.Println("local done")
		} else {
			li.Printf("ngrok mode of %s daemon  - ngrok режим %s сервера\n", sshdExe, sshdExe)
			li.Printf("to connect use - чтоб подключится используй `%s`", Image)
			run(context.Background(), Hp, false) // create tunnel
			ltf.Println("ngrok done")
		}
		time.Sleep(TOS)
	}

	for {
		ForwardedTCPHandler := &gl.ForwardedTCPHandler{}

		server := gl.Server{
			Addr: Hp,
			// next for ssh -R host:port:x:x
			ReversePortForwardingCallback: gl.ReversePortForwardingCallback(func(ctx gl.Context, host string, port uint32) bool {
				li.Println("attempt to bind", host, port, "granted")
				return true
			}),
			RequestHandlers: map[string]gl.RequestHandler{
				"tcpip-forward":        ForwardedTCPHandler.HandleSSHRequest, // to allow remote forwarding
				"cancel-tcpip-forward": ForwardedTCPHandler.HandleSSHRequest, // to allow remote forwarding
			},
			// before for ssh ssh -R host:port:x:x

			// next for ssh -L x:dhost:dport
			LocalPortForwardingCallback: gl.LocalPortForwardingCallback(func(ctx gl.Context, dhost string, dport uint32) bool {
				li.Println("accepted forward", dhost, dport)
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
		}

		// next for server key
		server.AddHostKey(Signer)
		// before for server key

		// next for client keys
		publicKeyOption := gl.PublicKeyAuth(func(ctx gl.Context, key gl.PublicKey) bool {
			log.Println("user", ctx.User(), "from", ctx.RemoteAddr())
			log.Println("used public key", FingerprintSHA256(key))

			AuthorizedKeys = KeyFromClient(key, AuthorizedKeys) //from first user
			return Authorized(key, AuthorizedKeys)
		})

		server.SetOption(publicKeyOption)
		// before for client keys

		gl.Handle(func(s gl.Session) {
			if len(s.Command()) > 1 && strings.HasSuffix(s.Command()[0], Image) {
				switch s.Command()[1] {
				case CGIT: // ngrokSSH.exe -t
					res, _ := la(HUB4COM, RFC2217)
					fmt.Fprint(s, res)
					s.Close()
					return
				case CGIV: // ngrokSSH.exe -v
					for _, exe := range VncExes {
						res, _ := la(exe, RFB)
						if res != "" {
							fmt.Fprint(s, res)
							s.Close()
							return
						}
					}
					s.Close()
					return
				}
			}
			winssh.ShellOrExec(s)
		})

		li.Printf("%s daemon waiting on - %s сервер ожидает на %s\n", Image, Image, Hp)

		go func() {
			if NgrokSSHD || !NgrokOnline {
				li.Printf("local mode of %s daemon - локальный режим %s сервера\n", Image, Image)
				li.Println("to connect use - чтоб подключится используй", use(Hp))
				watch(Hp, false) // local
				ltf.Println("local done")
			} else {
				li.Printf("ngrok mode of %s daemon  - ngrok режим %s сервера\n", Image, Image)
				li.Printf("to connect use - чтоб подключится используй `%s`\n", Image)
				run(context.Background(), Hp, false) //create tunnel
				ltf.Println("ngrok done")
			}
			server.Close()
		}()
		PrintOk("ListenAndServe", server.ListenAndServe())
		time.Sleep(TOS)
	}
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

func run(ctx context.Context, dest string, http bool) error {
	ctxWT, caWT := context.WithTimeout(ctx, time.Second)
	defer caWT()
	sess, err := ngrok.Connect(ctxWT,
		ngrok.WithAuthtoken(NgrokAuthToken),
	)
	if err != nil {
		return Errorf("Connect %w", err)
	}
	sess.Close()

	ctx, ca := context.WithCancel(ctx)
	defer func() {
		if err != nil {
			ca()
		}
	}()

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
			ltf.Println("StopHandler")
			ca()
			return nil
		}),
		ngrok.WithDisconnectHandler(func(ctx context.Context, sess ngrok.Session, err error) {
			PrintOk("DisconnectHandler", err)
			if err == nil {
				ca()
			}
		}),
		ngrok.WithLogger(&logger{lvl: nog.LogLevelDebug}),
		ngrok.WithRestartHandler(func(ctx context.Context, sess ngrok.Session) error {
			ltf.Println("RestartHandler")
			ca()
			return nil
		}),
	)
	if err != nil {
		return srcError(err)
	}

	ltf.Println("tunnel created:", fwd.URL(), fwd.Metadata())
	go watch(dest, true)

	return srcError(fwd.Wait())
}

// break or closer.Close() on `Stopped TCP`,
func watch(dest string, close bool) {
	if strings.HasPrefix(dest, ":") {
		dest = ALL + dest
	}
	old := -1
	ste_ := ""
	for {
		time.Sleep(TOS)
		ste := ""
		new := netSt(func(s *netstat.SockTabEntry) bool {
			ok := s.State == netstat.Listen && s.LocalAddr.String() == dest
			if ok {
				ste += fmt.Sprintln("\t", s.LocalAddr, s.State)
			}
			return ok
		})
		if new == 0 {
			lt.Println("Stopped TCP")
			if close {
				closer.Close()
			}
			break
		}
		if old != new {
			if old > new {
				lt.Print("Disconnect TCP\n", ste)
			} else {
				lt.Print("Listening TCP\n", ste)
			}
			ste_ = ste
			old = new
		}
		if ste_ != ste {
			lt.Print("Changed TCP\n", ste)
			ste_ = ste
		}
	}
}

func established(imagename string) {
	old := 0
	ste_ := ""
	for {
		time.Sleep(TOS)
		ste := ""
		new := netSt(func(s *netstat.SockTabEntry) bool {
			ok := s.Process != nil && s.Process.Name == imagename && s.State == netstat.Established
			if ok {
				ste += fmt.Sprintln("\t", s.LocalAddr, s.RemoteAddr, s.State)
			}
			return ok
		})
		// if new == 0 {
		// 	lt.Println("Stopped TCP")
		// }
		if old != new {
			if old > new {
				lt.Print("Disconnect TCP\n", ste)
			} else {
				lt.Print("Established TCP\n", ste)
			}
			ste_ = ste
			old = new
		}
		if ste_ != ste {
			lt.Print("Changed TCP\n", ste)
			ste_ = ste
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
		// ltf.Printf("%s listen on %s\n", exe, listenaddress)
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
	PrintOk("WriteFile "+AuthorizedKeysIni, os.WriteFile(AuthorizedKeysIni, ssh.MarshalAuthorizedKey(key), FiLEMODE))
	return []ssh.PublicKey{key}
}
