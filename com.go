package main

import (
	"os"
	"os/exec"
)

func com(hphp []string, so string) {
	opts := []string{"--baud=75",
		"--interface=" + hphp[0],
		"--create-filter=escparse,com,parse",
		"--create-filter=purge,com,purge",
		"--create-filter=pinmap,com,pinmap:--rts=cts --dtr=dsr --break=break",
		"--create-filter=linectl,com,lc:--br=remote --lc=remote",
		"--add-filters=0:com",

		"--create-filter=telnet,tcp,telnet:--comport=server --suppress-echo=yes",
		"--create-filter=lsrmap,tcp,lsrmap",
		"--create-filter=pinmap,tcp,pinmap:--cts=cts --dsr=dsr --dcd=dcd --ring=ring",
		"--create-filter=linectl,tcp,lc:--br=local --lc=local",
	}
	if Crypt != "" {
		opts = append(opts, Crypt)
	}
	Hub = exec.Command(Fns[HUB4COM], append(opts,
		"--add-filters=1:tcp",

		// "--use-driver=ser",
		"--octs=off",
		"--ito="+ITO,
		"--ox="+XO,
		"--ix="+XO,
		"--write-limit="+LIMIT,
		`\\.\COM`+so,

		"--use-driver=tcp",
		hphp[1],
	)...)
	Hub.Stdout = os.Stdout
	Hub.Stderr = os.Stderr
	go func() {
		li.Println(cmd("Run", Hub))
		PrintOk(cmd("Close", Hub), srcError(Hub.Run()))
	}()
}
