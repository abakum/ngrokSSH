package main

import (
	"bytes"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/f1bonacc1/glippy"
	"gopkg.in/ini.v1"
)

const (
	KITTYINI = "kitty.ini"
)

// start hub4com then show menu for baud and delay
func tty(hphp ...string) {
	if So == "" {
		return
	}
	li.Println("COM"+So, "com0com", Cncb)

	opts := []string{"--baud=75",
		"--create-filter=escparse,com,parse",
		"--create-filter=pinmap,com,pinmap:--rts=cts --dtr=dsr",
		"--create-filter=linectl,com,lc:--br=local --lc=local",
		"--add-filters=0:com",

		"--create-filter=telnet,tcp,telnet:--comport=client",
		"--create-filter=pinmap,tcp,pinmap:--rts=cts --dtr=dsr --break=break",
		"--create-filter=linectl,tcp,lc:--br=remote --lc=remote",
	}
	if Crypt != "" {
		opts = append(opts, Crypt)
	}
	Hub = exec.Command(Fns[HUB4COM], append(opts,
		"--add-filters=1:tcp",

		// "--use-driver=serial",
		"--octs=off",
		"--ito="+ITO,
		"--ox="+XO,
		"--ix="+XO,
		"--write-limit="+LIMIT,
		Cncb,

		"--use-driver=tcp",
		net.JoinHostPort(hphp[0], hphp[1]),
	)...)

	var bBuffer bytes.Buffer
	Hub.Stdout = &bBuffer
	Hub.Stderr = &bBuffer
	Println(cmd("Start", Hub), Hub.Start())

	defer kill()
	for i := 0; i < 24; i++ {
		s, er := bBuffer.ReadString('\n')
		if er == nil {
			FatalOr(s, strings.Contains(s, "ERROR"))
			fmt.Print(s)
			if s == "TCP(1): Connected\n" {
				break
			}
		}
		time.Sleep(time.Millisecond * 50)
	}
	// fmt.Print(bBuffer.String())
	bBuffer.WriteTo(os.Stdout)
	Hub.Stdout = os.Stdout
	Hub.Stderr = os.Stderr

	items := []func(index int) string{}
	items = append(items, func(index int) string {
		return setDelay(index, DELAY)
	})
	items = append(items, func(index int) string {
		return kiRun(index, "115200")
	})
	items = append(items, func(index int) string {
		return setDelay(index, "0.2")
	})
	items = append(items, func(index int) string {
		return kiRun(index, "38400")
	})
	items = append(items, func(index int) string {
		return setDelay(index, "0.4")
	})
	items = append(items, func(index int) string {
		return kiRun(index, "57600")
	})
	items = append(items, func(index int) string {
		return setDelay(index, "0.6")
	})
	items = append(items, func(index int) string {
		return setDelay(index, "0.7")
	})
	items = append(items, func(index int) string {
		return setDelay(index, "0.08")
	})
	items = append(items, func(index int) string {
		return kiRun(index, B9600)
	})

	menu(func(i int, d rune) string {
		if Delay != DELAY {
			return "Choose baud and seconds delay for Ctrl-F2 or commands from clipboard\n" +
				"Выбери скорость и задержку в секундах для Ctrl-F2 или команд из буфера"
		}
		return "Choose baud and seconds delay for Ctrl-F2\n" +
			"Выбери скорость и задержку в секундах для Ctrl-F2"
	},
		MARK, '9', actual(flag.CommandLine, Baud), true, items...)
}

func setDelay(index int, d string) string {
	mark := ""
	if Delay == d {
		mark = string(MARK)
	}
	if index > -1 {
		return fmt.Sprintf(`%s%d) %s`, mark, index, d)
	}
	Delay = d
	return ""
}

func kiRun(index int, b string) string {
	mark := ""
	if Baud == b {
		mark = string(MARK)
	}
	if index > -1 {
		return fmt.Sprintf(`%s%d) %s`, mark, index, b)
	}
	Baud = b
	opts := []string{
		"-sercfg",
		Baud,
		"-serial",
		"COM" + So,
	}
	Println("cmdFromClipBoard", command(&opts))
	ki := exec.Command(Fns[KITTY], opts...)

	ltf.Println(cmd("Run", ki))
	Println(cmd("Close", ki), ki.Run())
	return ""
}

func kill() {
	if Hub.Process != nil {
		Println(cmd("Kill", Hub), Hub.Process.Kill())
		// time.Sleep(time.Second)
	}
}

func SetValue(section *ini.Section, key, val string) (set bool) {
	set = section.Key(key).String() != val
	if set {
		ltf.Println(key, val)
		section.Key(key).SetValue(val)
	}
	return
}

func command(opts *[]string) error {
	ini.PrettyFormat = false
	iniFile, err := ini.LoadSources(ini.LoadOptions{
		IgnoreInlineComment: false,
	}, Fns[KITTYINI])
	if err != nil {
		return err
	}
	section := iniFile.Section("KiTTY")
	ok := SetValue(section, "commanddelay", Delay)
	if ok {
		err = iniFile.SaveTo(Fns[KITTYINI])
		if err != nil {
			return err
		}
	}
	if Delay == DELAY {
		return nil
	}
	text, err := glippy.Get()
	if err != nil {
		return err
	}
	if text == "" {
		return fmt.Errorf("empty ClipBoard")
	}
	temp, err := os.CreateTemp("", "cmdFromClipBoard")
	if err != nil {
		return err
	}
	clip := temp.Name()
	defer os.Remove(clip)
	n, err := temp.WriteString(text)
	if err != nil {
		return err
	}
	if n != len(text) {
		return fmt.Errorf("error write ClipBoard to %s", clip)
	}
	*opts = append(*opts,
		"-cmd",
		clip,
	)
	return nil
}
