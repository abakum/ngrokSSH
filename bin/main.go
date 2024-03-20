package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"internal/tool"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

func main() {
	const (
		ROOT        = "bin"
		FiLEMODE    = 0644
		CA          = "kitty.rnd"
		KNOWN_HOSTS = "known_hosts.ini"
	)
	flag.Parse()
	tool.Priv(flag.Arg(0), flag.Arg(1))
	wd, err := os.Getwd()
	Panic(err)

	name := filepath.Join(wd, ROOT, CA)
	_, err = os.Stat(name)
	if err == nil {
		os.Exit(0)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	Panic(err)

	data, err := x509.MarshalPKCS8PrivateKey(key)
	Panic(err)

	err = os.WriteFile(name, data, FiLEMODE)
	Panic(err)

	PublicKey, err := ssh.NewPublicKey(&key.PublicKey)
	Panic(err)

	bb := bytes.NewBufferString("@cert-authority * ")
	caPub := ssh.MarshalAuthorizedKey(PublicKey)
	bb.Write(caPub)

	bb.WriteString("* ")
	bb.Write(caPub)

	err = os.WriteFile(filepath.Join(wd, ROOT, KNOWN_HOSTS), bb.Bytes(), FiLEMODE)
	Panic(err)
}

func Panic(err error) {
	if err != nil {
		panic(err)
	}
}
