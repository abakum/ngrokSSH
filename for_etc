//go:build !windows
// +build !windows

package main

import (
	"os"
	"runtime"
	"strings"
)

func userName() string {
	return os.Getenv("USER")
}

func banner() string {
	goos := runtime.GOOS
	return strings.Join([]string{
		Imag,
		Ver,
		goos,
	}, "_")
}
