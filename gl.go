package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"

	"github.com/anmitsu/go-shlex"
	"github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"
)

const (
	agentRequestType = "auth-agent-req@openssh.com"
	agentChannelType = "auth-agent@openssh.com"
	maxSigBufSize    = 128

	agentTempDir    = "auth-agent"
	agentListenFile = "listener.sock"
)

func SessionHandler(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
	ch, reqs, err := newChan.Accept()
	if err != nil {
		// TODO: trigger event callback
		return
	}
	sess := &session{
		Channel:           ch,
		conn:              conn,
		handler:           srv.Handler,
		ptyCb:             srv.PtyCallback,
		sessReqCb:         srv.SessionRequestCallback,
		subsystemHandlers: srv.SubsystemHandlers,
		ctx:               ctx,
	}
	sess.handleRequests(reqs)
}

type session struct {
	sync.Mutex
	gossh.Channel
	conn              *gossh.ServerConn
	handler           ssh.Handler
	subsystemHandlers map[string]ssh.SubsystemHandler
	handled           bool
	exited            bool
	pty               *ssh.Pty
	winch             chan ssh.Window
	env               []string
	ptyCb             ssh.PtyCallback
	sessReqCb         ssh.SessionRequestCallback
	rawCmd            string
	subsystem         string
	ctx               ssh.Context
	sigCh             chan<- ssh.Signal
	sigBuf            []ssh.Signal
	breakCh           chan<- bool
	agent             bool
}

func (sess *session) Write(p []byte) (n int, err error) {
	if sess.pty != nil {
		m := len(p)
		// normalize \n to \r\n when pty is accepted.
		// this is a hardcoded shortcut since we don't support terminal modes.
		p = bytes.Replace(p, []byte{'\n'}, []byte{'\r', '\n'}, -1)
		p = bytes.Replace(p, []byte{'\r', '\r', '\n'}, []byte{'\r', '\n'}, -1)
		n, err = sess.Channel.Write(p)
		if n > m {
			n = m
		}
		return
	}
	return sess.Channel.Write(p)
}

func (sess *session) PublicKey() ssh.PublicKey {
	sessionkey := sess.ctx.Value(ssh.ContextKeyPublicKey)
	if sessionkey == nil {
		return nil
	}
	return sessionkey.(ssh.PublicKey)
}

func (sess *session) Permissions() ssh.Permissions {
	// use context permissions because its properly
	// wrapped and easier to dereference
	perms := sess.ctx.Value(ssh.ContextKeyPermissions).(*ssh.Permissions)
	return *perms
}

func (sess *session) Context() ssh.Context {
	return sess.ctx
}

func (sess *session) Exit(code int) error {
	sess.Lock()
	defer sess.Unlock()
	if sess.exited {
		return errors.New("Session.Exit called multiple times")
	}
	sess.exited = true

	status := struct{ Status uint32 }{uint32(code)}
	_, err := sess.SendRequest("exit-status", false, gossh.Marshal(&status))
	if err != nil {
		return err
	}
	return sess.Close()
}

func (sess *session) User() string {
	return sess.conn.User()
}

func (sess *session) RemoteAddr() net.Addr {
	return sess.conn.RemoteAddr()
}

func (sess *session) LocalAddr() net.Addr {
	return sess.conn.LocalAddr()
}

func (sess *session) Environ() []string {
	return append([]string(nil), sess.env...)
}

func (sess *session) RawCommand() string {
	return sess.rawCmd
}

func (sess *session) Command() []string {
	cmd, _ := shlex.Split(sess.rawCmd, true)
	return append([]string(nil), cmd...)
}

func (sess *session) Subsystem() string {
	return sess.subsystem
}

func (sess *session) Pty() (ssh.Pty, <-chan ssh.Window, bool) {
	if sess.pty != nil {
		return *sess.pty, sess.winch, true
	}
	return ssh.Pty{}, sess.winch, false
}

func (sess *session) Signals(c chan<- ssh.Signal) {
	sess.Lock()
	defer sess.Unlock()
	sess.sigCh = c
	if len(sess.sigBuf) > 0 {
		go func() {
			for _, sig := range sess.sigBuf {
				sess.sigCh <- sig
			}
		}()
	}
}

func (sess *session) Break(c chan<- bool) {
	sess.Lock()
	defer sess.Unlock()
	sess.breakCh = c
}

func parsePtyRequest(s []byte) (pty ssh.Pty, ok bool) {
	term, s, ok := parseString(s)
	if !ok {
		return
	}
	width32, s, ok := parseUint32(s)
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if !ok {
		return
	}
	pty = ssh.Pty{
		Term: term,
		Window: ssh.Window{
			Width:  int(width32),
			Height: int(height32),
		},
	}
	return
}

func parseUint32(in []byte) (uint32, []byte, bool) {
	if len(in) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(in), in[4:], true
}

func parseString(in []byte) (out string, rest []byte, ok bool) {
	if len(in) < 4 {
		return
	}
	length := binary.BigEndian.Uint32(in)
	if uint32(len(in)) < 4+length {
		return
	}
	out = string(in[4 : 4+length])
	rest = in[4+length:]
	ok = true
	return
}

func parseWinchRequest(s []byte) (win ssh.Window, ok bool) {
	width32, s, ok := parseUint32(s)
	if width32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	height32, _, ok := parseUint32(s)
	if height32 < 1 {
		ok = false
	}
	if !ok {
		return
	}
	win = ssh.Window{
		Width:  int(width32),
		Height: int(height32),
	}
	return
}
