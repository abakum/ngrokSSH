package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/dolmen-go/contextio"
	termm "github.com/moby/term"
	"golang.org/x/term"

	windowsconsole "github.com/abakum/ngrokSSH/windows"
	"github.com/eiannone/keyboard"
)

func main() {
	menu()
}

func mn(char rune) {
	const EXIT = "exit\r\n"
	var s *exec.Cmd
	switch char {
	case '1':
		s = exec.Command("cmd")
		s.Stdin, s.Stdout, s.Stderr = os.Stdin, os.Stdout, os.Stderr
		fmt.Println("Run", s.String())
		fmt.Println("Stop", s.String(), s.Run())
	case '2':
		s = exec.Command("cmd")
		stdin, err := windowsconsole.DuplicateFile(os.Stdin)
		// stdin, err := cancelreader.NewReader(os.Stdin)
		if err != nil {
			return
		}
		defer stdin.Close()

		s.Stdin = stdin
		or, err := s.StdoutPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stdout, or))
			fmt.Println(" out")
		}()

		er, err := s.StderrPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stderr, er))
			fmt.Println(" err")
		}()

		fmt.Println("Run", s.String())
		fmt.Println("Stop", s.String(), s.Run())
	case '3':
		s = exec.Command("cmd")
		iw, err := s.StdinPipe()
		if err != nil {
			return
		}

		stdin, err := windowsconsole.DuplicateFile(os.Stdin)
		if err != nil {
			return
		}
		defer stdin.Close()

		go func() {
			fmt.Print(io.Copy(iw, stdin))
			fmt.Println(" in")
		}()

		or, err := s.StdoutPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stdout, or))
			fmt.Println(" out")
		}()

		er, err := s.StderrPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stderr, er))
			fmt.Println(" err")
		}()

		fmt.Println("Start", s.String(), s.Start())
		if err != nil {
			return
		}

		fmt.Println("Stop", s.String(), s.Wait())
	case '4':
		s = exec.Command("cmd")
		iw, err := s.StdinPipe()
		if err != nil {
			return
		}

		or, err := s.StdoutPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stdout, or))
			fmt.Println(" out")
		}()

		er, err := s.StderrPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stderr, er))
			fmt.Println(" err")
		}()

		// stdin, err := windowsconsole.DuplicateFile(os.Stdin)
		// if err != nil {
		// 	return
		// }
		// defer stdin.Close()

		// cancel, err := cancelreader.NewReader(os.Stdin)
		// if err != nil {
		// 	return
		// }
		// defer cancel.Close()

		fmt.Println("Start", s.String(), s.Start())
		if err != nil {
			return
		}

		go func() {
			fmt.Println("Stop", s.String(), s.Wait())
			// fmt.Println("Press Enter")
			// fmt.Println(cancel.Cancel())
			// fmt.Println("stdin.Close", stdin.Close())
		}()

		// fmt.Print(io.Copy(iw, cancel))
		// fmt.Print(io.Copy(iw, stdin))
		fmt.Print(copyB(iw, os.Stdin, EXIT))
		fmt.Println(" in")

	case '5':
		s = exec.CommandContext(context.Background(), "cmd")
		cancel := func() {
			fmt.Println("Cancel")
			s.Cancel()
		}

		iw, err := s.StdinPipe()
		if err != nil {
			return
		}

		or, err := s.StdoutPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stdout, or))
			fmt.Println(" out")
			cancel()
		}()

		er, err := s.StderrPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stderr, er))
			fmt.Println(" err")
			cancel()
		}()

		fmt.Println("Start", s.Args, s.Start())
		if err != nil {
			return
		}
		go func() {
			fmt.Println("Stop", s.Args, s.Wait())
			fmt.Println("Press Enter")
			cancel()
		}()

		fmt.Print(io.Copy(iw, os.Stdin))
		fmt.Println(" in")

	case '6':
		ctx, ca := context.WithCancel(context.Background())
		s = exec.Command("cmd")
		cancel := func() {
			fmt.Println("ca")
			ca()
		}

		s.Stdin = contextio.NewReader(ctx, os.Stdin)

		or, err := s.StdoutPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stdout, or))
			fmt.Println(" out")
			cancel()
		}()

		er, err := s.StderrPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stderr, er))
			fmt.Println(" err")
			cancel()
		}()

		fmt.Println("Run", s.String())
		fmt.Println("Stop", s.String(), s.Run())
	case '7':
		statesPrint()
		defer statesPrint()

		s = exec.Command("cmd")
		si, err := termm.SetRawTerminal(os.Stdin.Fd())
		if err != nil {
			return
		}
		defer termm.RestoreTerminal(os.Stdin.Fd(), si)
		statesPrint()

		stdin, err := windowsconsole.DuplicateFile(os.Stdin)
		if err != nil {
			return
		}
		defer stdin.Close()

		s.Stdin = stdin
		s.Stdout = os.Stdout
		s.Stdin = os.Stdin

		fmt.Println("Run", s.String())
		fmt.Println("Stop", s.String(), s.Run())
	case '8':
		statesPrint()
		defer statesPrint()
		s = exec.Command("cmd")
		si, err := termm.SetRawTerminal(os.Stdin.Fd())
		if err != nil {
			return
		}
		defer termm.RestoreTerminal(os.Stdin.Fd(), si)
		statesPrint()

		stdin, err := windowsconsole.DuplicateFile(os.Stdin)
		if err != nil {
			return
		}
		defer stdin.Close()

		// s.Stdin = stdin
		iw, err := s.StdinPipe()
		if err != nil {
			return
		}

		or, err := s.StdoutPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stdout, or))
			fmt.Println(" out")
		}()

		er, err := s.StderrPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stderr, er))
			fmt.Println(" err")
		}()

		fmt.Println("Start", s.String(), s.Start())
		if err != nil {
			return
		}

		go func() {
			fmt.Println("Stop", s.String(), s.Wait())
			fmt.Println("Press Enter")
		}()

		fmt.Print(copyB(iw, stdin, EXIT))
		// fmt.Print(copyBuffer(iw, stdin, nil))
		fmt.Println(" in")
	case '9':
		s = exec.Command("cmd")
		iw, err := s.StdinPipe()
		if err != nil {
			return
		}

		or, err := s.StdoutPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stdout, or))
			fmt.Println(" out")
		}()

		er, err := s.StderrPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(os.Stderr, er))
			fmt.Println(" err")
		}()

		oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
		if err != nil {
			return
		}
		defer term.Restore(int(os.Stdin.Fd()), oldState)

		fmt.Println("Start", s.String(), s.Start())
		if err != nil {
			return
		}

		go func() {
			fmt.Println("Stop", s.String(), s.Wait())
		}()
		b := make([]byte, 1)
		for {
			_, err = os.Stdin.Read(b)
			if err != nil {
				return
			}
			iw.Write(b)
		}
	}
}

// from io
var errInvalidWrite = errors.New("invalid write result")

// from io
func copyB(dst io.Writer, src io.Reader, EXIT string) (written int64, err error) {
	var errEXIT = fmt.Errorf("was copied EXIT: %q", EXIT)
	buf := make([]byte, 1)
	exit := []byte(EXIT)
	fifo := bytes.Clone(exit)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw < 0 || nr < nw {
				nw = 0
				if ew == nil {
					ew = errInvalidWrite
				}
			}
			written += int64(nw)
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
			fifo = append(fifo[1:], buf[0])
			if bytes.EqualFold(fifo, exit) {
				err = errEXIT
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func statesPrint() {
	fd := os.Stdin.Fd()
	s, err := term.GetState(int(fd))
	fmt.Println(fd, s, err)

	fd = os.Stdout.Fd()
	s, err = term.GetState(int(fd))
	fmt.Println(fd, s, err)

	fd = os.Stderr.Fd()
	s, err = term.GetState(int(fd))
	fmt.Println(fd, s, err)
}

func menu() {
	enter := true
	get := getEnter
	for {
		fmt.Println()
		fmt.Println(0, "getEnter", enter)
		fmt.Println(1, "ok! all direct: s.Stdin, s.Stdout, s.Stderr = os.Stdin, os.Stdout, os.Stderr")
		fmt.Println(2, "ok! os.Stdout, os.Stderr over pipe")
		fmt.Println(3, "bug! all over pipe")
		fmt.Println(4, "ok! as 3) but with copyB")
		fmt.Println(5, "bug! as 3) but with CommandContext")
		fmt.Println(6, "bug! as 3) but with contextio")
		fmt.Println(7, "bug! target by direct")
		fmt.Println(8, "bug! target over pipe")
		fmt.Println(9, "bug! cmd is term")
		fmt.Println("Select")
		switch char := get(); char {
		case '0':
			enter = !enter
			get = getKey
			if enter {
				get = getEnter
			}
		case '1', '2', '3', '4', '5', '6', '7', '8', '9':
			mn(char)
		default:
			return
		}
	}
}
func getKey() rune {
	if err := keyboard.Open(); err != nil {
		return ' '
	}
	defer func() {
		_ = keyboard.Close()
	}()
	for {
		char, key, err := keyboard.GetKey()
		fmt.Printf("You pressed %q\n", char)
		if key != 0 {
			fmt.Printf("You pressed key %X\n", key)
		}
		if err != nil {
			return ' '
		}
		switch char {
		case '\r', '\n':
			continue
		}
		return char
	}
}

func getEnter() rune {
	var char rune
	for {
		fmt.Scanf("%c\n", &char)
		// fmt.Scanln("%c", &char)
		fmt.Printf("You enter %q\n", char)
		switch char {
		case '\r', '\n':
			continue
		}
		return char
	}
}
func readLine() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("pipe not supported")
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return "", fmt.Errorf("failed setting stdin to raw mode: %w", err)
	}
	tty := term.NewTerminal(os.Stdin, "")
	line, err := tty.ReadLine()
	_ = term.Restore(int(os.Stdin.Fd()), oldState)

	if err != nil {
		return "", fmt.Errorf("failed to read from stdin: %w", err)
	}
	return line, nil
}
