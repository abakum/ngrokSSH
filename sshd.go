package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
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

func server() {
	if count != 1 {
		li.Println("another one has been launched - запущен ещё один", imagename)
	}

	// if sshd of OpenSSH use listenaddress==hp then use it else start nfrokSSH daemon
	// если sshd от OpenSSH использует listenaddress==hp то он будет использоваться в противном случае запустится сервер nfrokSSH
	if listenaddress, _ := openSSHD(); listenaddress == hp {
		// to prevent disconnect by idle set `ClientAliveInterval 100`
		li.Printf("%s daemon waiting on - %s сервер ожидает на %s\n", sshdExe, sshdExe, hp)
		if ngrokSSHD || !ngrokOnline {
			li.Printf("local mode of %s daemon  - локальный режим %s сервера\n", sshdExe, sshdExe)
			li.Println("to connect use - чтоб подключится используй", use(hp))
			watch(hp, false) // local
		} else {
			li.Printf("ngrok mode of %s daemon  - ngrok режим %s сервера\n", sshdExe, sshdExe)
			li.Printf("to connect use - чтоб подключится используй `%s`", imagename)
			run(context.Background(), hp, false) // create tunnel
		}
		return
	}

	ForwardedTCPHandler := &gl.ForwardedTCPHandler{}

	server := gl.Server{
		Addr: hp,
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
		IdleTimeout:            -time.Second * 100, // send `keepalive` every 100 seconds
		MaxTimeout:             -time.Second * 300, // сlosing the session after 300 seconds with no response
	}
	closer.Bind(func() {
		err = server.Close()
	})

	// next for server key
	pri := winssh.GetHostKey(cwd) // /etc/ssh
	pemBytes, err := os.ReadFile(pri)
	var key gl.Signer
	if err != nil {
		key, err = winssh.GenerateSigner(pri)
	} else {
		key, err = ssh.ParsePrivateKey(pemBytes)
	}
	if err != nil {
		return
	}
	server.AddHostKey(key)
	if len(server.HostSigners) < 1 {
		err = srcError(fmt.Errorf("private keys for the host key, must have at least one"))
		return
	}
	hpk := server.HostSigners[0].PublicKey()
	log.Println("HostKey", ssh.FingerprintSHA256(hpk))
	// before for server key

	// next for client keys
	authorized := winssh.GetUserKeys(cwd)                              //.ssh
	authorized = winssh.BytesToAuthorized(authorized_keys, authorized) //from embed

	publicKeyOption := gl.PublicKeyAuth(func(ctx gl.Context, key gl.PublicKey) bool {
		log.Println("user", ctx.User(), "from", ctx.RemoteAddr())
		log.Println("used public key", ssh.FingerprintSHA256(key))

		authorized = winssh.KeyToAuthorized(key, authorized) //from first user
		return winssh.Authorized(key, authorized)
	})

	server.SetOption(publicKeyOption)
	// before for client keys

	gl.Handle(func(s gl.Session) {
		fmt.Fprint(s, "Please add to file - Добавьте в файл: ~/.ssh/known_hosts line - строку:\n* ", string(ssh.MarshalAuthorizedKey(hpk)))
		winssh.ShellOrExec(s)
	})

	li.Printf("%s daemon waiting on - %s сервер ожидает на %s\n", imagename, imagename, hp)

	go func() {
		if ngrokSSHD || !ngrokOnline {
			li.Printf("local mode of %s daemon - локальный режим %s сервера\n", imagename, imagename)
			li.Println("to connect use - чтоб подключится используй", use(hp))
			watch(hp, false) // local
		} else {
			li.Printf("ngrok mode of %s daemon  - ngrok режим %s сервера\n", imagename, imagename)
			li.Printf("to connect use - чтоб подключится используй `%s`\n", imagename)
			run(context.Background(), hp, false) //create tunnel
		}
	}()
	PrintOk("ListenAndServe", server.ListenAndServe())

}

func use(hp string) (s string) {
	h, p, _ := net.SplitHostPort(hp)
	if p == PORT {
		p = ""
	}
	if h != "" {
		return fmt.Sprintf("`%s`", strings.Trim(imagename+" "+net.JoinHostPort(h, p), " :"))
	}
	s = ""
	for _, h := range ips {
		s += fmt.Sprintf("\n\t`%s`", strings.Trim(imagename+" "+net.JoinHostPort(h, p), " :"))
	}
	return
}

func openSSHD() (hp string, ok bool) {
	tabs, err := netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
		if s.Process != nil {
			if s.State == netstat.Listen {
				if s.Process.Name == imagename {
					ltf.Printf("%s listen on %s\n", imagename, s.LocalAddr.String())
					return false
				}
				if s.LocalAddr.Port == 22 {
					sshdExe = s.Process.Name
					return true
				}
				return s.Process.Name == sshdExe
			}
		} else {
			return s.State == netstat.Listen && s.LocalAddr.Port == 22
		}
		return false
	})
	if err != nil {
		return
	}
	for _, s := range tabs {
		hp = s.LocalAddr.String()
		ltf.Println(sshdExe, "listen on", hp)
		ok = true
		return
	}
	return
}

// for `ssh :`
func withMetadata(lPort string) (meta string) {
	h, p, err := net.SplitHostPort(lPort)
	if err != nil {
		p = PORT
	}
	if h == ALL || h == "" {
		h = strings.Join(ips, ",")
	}
	return fmt.Sprintf("%s@%s:%s", os.Getenv("USERNAME"), h, p)
}

func run(ctx context.Context, dest string, http bool) error {
	ctxWT, caWT := context.WithTimeout(ctx, time.Second)
	defer caWT()
	sess, err := ngrok.Connect(ctxWT,
		ngrok.WithAuthtoken(NGROK_AUTHTOKEN),
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
		ngrok.WithAuthtoken(NGROK_AUTHTOKEN),
		ngrok.WithStopHandler(func(ctx context.Context, sess ngrok.Session) error {
			go func() {
				time.Sleep(TOM)
				ca()
			}()
			return nil
		}),
		ngrok.WithDisconnectHandler(func(ctx context.Context, sess ngrok.Session, err error) {
			PrintOk("WithDisconnectHandler", err)
			if err == nil {
				go func() {
					time.Sleep(TOM)
					ca()
				}()
			}
		}),
		ngrok.WithLogger(&logger{lvl: nog.LogLevelDebug}),
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
