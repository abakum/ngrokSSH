package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/dolmen-go/contextio"
	termm "github.com/moby/term"
	"github.com/muesli/cancelreader"
	"golang.org/x/term"

	windowsconsole "github.com/abakum/ngrokSSH/windows"
	"github.com/eiannone/keyboard"
)

func main() {
	menu()
}

func mn(char rune) {
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
		// s.WaitDelay = time.Second
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

		cancel, err := cancelreader.NewReader(os.Stdin)
		if err != nil {
			return
		}
		defer cancel.Close()

		fmt.Println("Start", s.String(), s.Start())
		if err != nil {
			return
		}

		go func() {
			fmt.Println("Stop", s.String(), s.Wait())
			fmt.Println("Press Enter")
			// fmt.Println(cancel.Close())
			fmt.Println(cancel.Cancel())
			// fmt.Println("stdin.Close", stdin.Close())
		}()

		fmt.Print(io.Copy(iw, cancel))
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

		so, err := termm.SetRawTerminalOutput(os.Stdout.Fd())
		if err != nil {
			return
		}
		defer termm.RestoreTerminal(os.Stdout.Fd(), so)

		se, err := termm.SetRawTerminalOutput(os.Stderr.Fd())
		if err != nil {
			return
		}
		defer termm.RestoreTerminal(os.Stderr.Fd(), se)

		s.Stdin, s.Stdout, s.Stderr = termm.StdStreams()

		// stdin, err := windowsconsole.NewAnsiReaderDuplicateFile(os.Stdin)
		// if err != nil {
		// 	return
		// }
		// defer stdin.Close()

		// s.Stdin = stdin

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

		so, err := termm.SetRawTerminalOutput(os.Stdout.Fd())
		if err != nil {
			return
		}
		defer termm.RestoreTerminal(os.Stdout.Fd(), so)

		se, err := termm.SetRawTerminalOutput(os.Stderr.Fd())
		if err != nil {
			return
		}
		defer termm.RestoreTerminal(os.Stderr.Fd(), se)

		_, Stdout, Stderr := termm.StdStreams()

		Stdin, err := windowsconsole.NewAnsiReaderDuplicateFile(os.Stdin)
		if err != nil {
			return
		}
		defer Stdin.Close()

		// s.Stdin = Stdin
		iw, err := s.StdinPipe()
		if err != nil {
			return
		}

		or, err := s.StdoutPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(Stdout, or))
			fmt.Println(" out")
		}()

		er, err := s.StderrPipe()
		if err != nil {
			return
		}
		go func() {
			fmt.Print(io.Copy(Stderr, er))
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

		fmt.Print(io.Copy(iw, Stdin))
		fmt.Println(" in")
	}
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
		fmt.Println(4, "bug! as 3) but with `Press Enter`")
		fmt.Println(5, "bug! as 4) but with CommandContext")
		fmt.Println(6, "bug! as 4) but with contextio")
		fmt.Println(7, "ok on win10, bag on win7! target by direct")
		fmt.Println(8, "bug! target over pipe")
		fmt.Println("Select")
		switch char := get(); char {
		case '0':
			enter = !enter
			get = getKey
			if enter {
				get = getEnter
			}
		case '1', '2', '3', '4', '5', '6', '7', '8':
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
func flushConsoleInputBuffer() {

}
