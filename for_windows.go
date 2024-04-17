//go:build windows
// +build windows

package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/windows"
)

func userName() string {
	return os.Getenv("USERNAME")
}

func banner() string {
	goos := runtime.GOOS
	majorVersion, minorVersion, buildNumber := windows.RtlGetNtVersionNumbers()
	goos = fmt.Sprintf("%s_%d.%d.%d", goos, majorVersion, minorVersion, buildNumber)
	return strings.Join([]string{
		Imag,
		Ver,
		goos,
	}, "_")
}
