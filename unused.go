package main

import (
	"fmt"
	"io"
	"log"
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

// bytesToHex converts a slice of bytes to a human-readable string.
func bytesToHex(b []byte) string {
	hex := make([]string, len(b))
	for i, ch := range b {
		hex[i] = fmt.Sprintf("%X", ch)
	}
	return strings.Join(hex, "")
}
