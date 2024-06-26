package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/abakum/go-ansiterm"
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
		Version: banner(),
	}

	// next for server key
	// server.AddHostKey(Signer)
	server.AddHostKey(certSigner(Signer, Signer, Imag)) //selfsigned ca
	// before for server key

	// next for client keys
	publicKeyOption := gl.PublicKeyAuth(func(ctx gl.Context, key gl.PublicKey) bool {
		Println("User", ctx.User(), "from", ctx.RemoteAddr())
		Println("key", FingerprintSHA256(key))
		if Authorized(key, AuthorizedKeys) {
			return true
		}

		cert, ok := key.(*ssh.Certificate)
		if !ok {
			return false
		}
		// next for certificate of client
		if cert.CertType != ssh.UserCert {
			Println(fmt.Errorf("ssh: cert has type %d", cert.CertType))
			return false
		}
		if !gl.KeysEqual(cert.SignatureKey, Signer.PublicKey()) {
			Println(fmt.Errorf("ssh: certificate signed by unrecognized authority %s", FingerprintSHA256(cert.SignatureKey)))
			return false
		}
		if err := CertCheck.CheckCert(Imag, cert); err != nil { //ctx.User()
			Println(err)
			return false
		}
		//  cert.Permissions
		Println("Authorized by certificate", FingerprintSHA256(cert.SignatureKey))
		return true

	})

	server.SetOption(publicKeyOption)
	// before for client keys

	gl.Handle(func(s gl.Session) {
		defer s.Exit(0)
		clientVersion := s.Context().ClientVersion()
		ltf.Println(clientVersion)
		if len(s.Command()) > 1 {
			base := filepath.Base(s.Command()[0])
			bas := strings.Split(base, ".")[0]
			if strings.EqualFold(bas, Imag) && s.Command()[1] == CGIR {
				caRW()
			}
		}
		if !strings.Contains(clientVersion, OSSH) {
			// Not for OpenSSH
			time.AfterFunc(time.Millisecond*333, func() {
				title := SetConsoleTitle(CutSSH2(s.Context().ClientVersion()) + "@" + CutSSH2(s.Context().ServerVersion()))
				s.Write([]byte(title))
			})
		}
		Println(len(s.Command()), s.Command(), s.RawCommand())
		winssh.ShellOrExec(s)
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

func certSigner(caSigner, hostSigner ssh.Signer, id string) ssh.Signer {
	mas, err := ssh.NewSignerWithAlgorithms(caSigner.(ssh.AlgorithmSigner), []string{caSigner.PublicKey().Type()})
	if err != nil {
		return hostSigner
	}
	certificate := ssh.Certificate{
		Key:         hostSigner.PublicKey(),
		CertType:    ssh.HostCert,
		KeyId:       id,
		ValidBefore: ssh.CertTimeInfinity,
	}
	err = certificate.SignCert(rand.Reader, mas)
	if err != nil {
		return hostSigner
	}
	certSigner, err := ssh.NewCertSigner(&certificate, hostSigner)
	if err != nil {
		return hostSigner
	}
	return certSigner
}

func CutSSH2(s string) string {
	after, _ := strings.CutPrefix(s, SSH2)
	return after

}

func SetConsoleTitle(s string) string {
	return fmt.Sprintf("%c]0;%s%c", ansiterm.ANSI_ESCAPE_PRIMARY, s, ansiterm.ANSI_BEL)
}

func un(ru string) (u string) {
	u = Ln
	if u == "" {
		u = ru
	}
	if u == "" || u == "_" {
		u = userName()
	}
	return
}

func use(hp string) (s string) {
	h, p, _ := net.SplitHostPort(hp)
	if p == PORT {
		p = ""
	}
	if h == LH && p == "" {
		return fmt.Sprintf("`%s _@`", Image)
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
			return Errorf("connect %w", err)
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
		return Errorf("parse %w", err)
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
			Println("Authorized")
			return true
		}
	}
	return false
}
