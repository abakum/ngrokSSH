package main

import (
	"fmt"
	"io"
	"log"
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
