package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"runtime"
	"strings"

	"github.com/mitchellh/go-ps"
	"github.com/xlab/closer"
)

const (
	ansiReset     = "\u001B[0m"
	ansiRedBGBold = "\u001B[41m\u001B[1m"
	BUG           = "Ж"
	ansiGreenFG   = "\u001B[32m\u001B[1m"
	GT            = ">"
)

var (
	letf = log.New(os.Stdout, BUG, log.Ltime|log.Lshortfile)
	let  = log.New(os.Stdout, BUG, log.Ltime)
	ltf  = log.New(os.Stdout, " ", log.Ltime|log.Lshortfile)
	lt   = log.New(os.Stdout, " ", log.Ltime)
	li   = log.New(os.Stdout, "\t", 0)
)

// color for ansi enabled console
func SetPrefix(a bool) {
	Bug = BUG
	Gt = GT
	if a {
		Bug = ansiRedBGBold + BUG + ansiReset
		Gt = ansiGreenFG + GT + ansiReset
	}
	letf.SetPrefix(Bug)
	let.SetPrefix(Bug)
}

// `choco install ansicon`
func isAnsi() (ok bool) {
	if os.Getenv("ANSICON") != "" {
		return true
	}
	parent, err := ps.FindProcess(os.Getppid())
	if err != nil {
		letf.Println(err)
		return
	}
	var PS = []string{"powershell.exe", "ansicon.exe", "conemuc.exe"}
	for _, exe := range PS {
		ok = strings.ToLower(parent.Executable()) == exe
		if ok {
			break
		}
	}
	SetPrefix(ok)
	return
}

// Get source of code
func src(depth int) (s string) {
	pc := make([]uintptr, 1)
	n := runtime.Callers(depth-5, pc)
	if n > 0 {
		frame, _ := runtime.CallersFrames(pc).Next()
		s = fmt.Sprintf("%s:%d:", path.Base(frame.File), frame.Line)
	}
	return
}

// Wrap source of code and message to error
func Errorf(format string, args ...any) error {
	return fmt.Errorf(src(8)+" %w", fmt.Errorf(format, args...))
}

// Wrap source of code and error to error
func srcError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf(src(8)+" %w", err)
}

func PrintOk(s string, err error) (ok bool) {
	ok = err == nil
	if ok {
		lt.Println(src(8), s, "ok")
	} else {
		let.Println(src(8), s, err)
	}
	return ok
}

func Println(v ...any) (ok bool) {
	anys := []any{src(8)}
	ok = true
	for _, a := range v {
		switch t := a.(type) {
		case nil:
			anys = append(anys, "Ф")
		case error:
			anys = append(anys, t)
			ok = false
		case string:
			if t != "" {
				anys = append(anys, t)
			}
		default:
			anys = append(anys, t)
		}
	}
	if ok {
		lt.Println(anys...)
	} else {
		let.Println(anys...)
	}
	return ok
}

func Fatal(err error) {
	if err != nil {
		let.Println(src(8), err)
		closer.Exit(1)
	}
}
func FatalOr(s string, cases ...bool) {
	for _, c := range cases {
		if c {
			let.Println(src(8), s)
			closer.Exit(1)
			break
		}
	}
}
func FatalAnd(s string, cases ...bool) {
	for _, c := range cases {
		if !c {
			return
		}
	}
	let.Println(src(8), s)
	closer.Exit(1)
}
