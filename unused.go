package main

import (
	"fmt"
	"io"
	"log"

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
