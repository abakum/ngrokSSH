package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path"
	"runtime/debug"
	"strings"
)

const (
	ansiReset = "\u001B[0m"
	ansiRedBG = "\u001B[41m"
	BUG       = ansiRedBG + "Ж" + ansiReset
)

var (
	letf = log.New(os.Stdout, BUG, log.Ltime|log.Lshortfile)
	ltf  = log.New(os.Stdout, " ", log.Ltime|log.Lshortfile)
	let  = log.New(os.Stdout, BUG, log.Ltime)
	lt   = log.New(os.Stdout, " ", log.Ltime)
	li   = log.New(os.Stdout, "\t", 0)
)

// Get source of code
func src(deep int) (s string) {
	s = string(debug.Stack())
	str := strings.Split(s, "\n")
	if l := len(str); l <= deep {
		deep = l - 1
		for k, v := range str {
			fmt.Println(k, v)
		}
	}
	s = str[deep]
	s = strings.Split(s, " +0x")[0]
	_, s = path.Split(s)
	s += ":"
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

func PrintOk(s string, err error) {
	if err != nil {
		let.Println(src(8), s, err)
	} else {
		lt.Println(src(8), s, "ok")
	}
}

func logOff() {
	for _, l := range []*log.Logger{letf, ltf, let, lt, li} {
		l.SetOutput(io.Discard)
	}
}

func pressEnter() {
	logOff()
	fmt.Print("Press Enter>")
	fmt.Scanln()
}
