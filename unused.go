package main

import (
	"fmt"
	"io"
	"log"
	"path"
	"runtime/debug"
	"strings"

	windowsconsole "github.com/moby/term/windows"
	"golang.org/x/sys/windows"
)

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

func GetStdout() io.Writer {
	h := uint32(windows.STD_OUTPUT_HANDLE)
	stdout := windowsconsole.NewAnsiWriter(int(h))

	return stdout
}

// Get source of code
func src_(deep int) (s string) {
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
