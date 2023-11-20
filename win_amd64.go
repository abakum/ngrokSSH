//go:build windows && amd64
// +build windows,amd64

package main

import (
	"embed"
)

//go:embed OpenSSH/amd64/*
var bin embed.FS
