package main

import (
	"os"
	"os/exec"
	"strconv"
)

func com() {
	if so == "" || rfc2217 == "" {
		return
	}
	h, p := LH, strconv.Itoa(RFC2217)
	hphp := parseHPHP(rfc2217, RFC2217)
	if len(hphp) > 2 {
		h, p = hphp[2], hphp[3]
	}

	opts = append(opts,
		"--interface="+h,
		"--create-filter=escparse,com,parse",
		"--create-filter=purge,com,purge",
		"--create-filter=pinmap,com,pinmap:--rts=cts --dtr=dsr --break=break",
		"--create-filter=linectl,com,lc:--br=remote --lc=remote",
		"--add-filters=0:com",

		"--create-filter=telnet,tcp,telnet:--comport=server --suppress-echo=yes",
		"--create-filter=lsrmap,tcp,lsrmap",
		"--create-filter=pinmap,tcp,pinmap:--cts=cts --dsr=dsr --dcd=dcd --ring=ring",
		"--create-filter=linectl,tcp,lc:--br=local --lc=local",
	)
	if crypt != "" {
		opts = append(opts, crypt)
	}
	hub = exec.Command(hub4com, append(opts,
		"--add-filters=1:tcp",

		// "--use-driver=ser",
		"--octs=off",
		"--ito="+ITO,
		"--ox="+XO,
		"--ix="+XO,
		"--write-limit="+LIMIT,
		`\\.\COM`+ser,

		"--use-driver=tcp",
		p,
	)...)
	hub.Stdout = os.Stdout
	hub.Stderr = os.Stderr
	go func() {
		li.Println(cmd("Run", hub))
		PrintOk(cmd("Close", hub), srcError(hub.Run()))
	}()
}
