package main

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/dixonwille/wmenu/v5"
	"github.com/f1bonacc1/glippy"
	"github.com/xlab/closer"
	"gopkg.in/ini.v1"
)

var (
	commandDelay = DELAY
	ok           bool
)

func tty(rfc2217 string) {
	hphp := parseHPHP(rfc2217, RFC2217)
	CNCB = `\\.\` + CNCB
	li.Println("COM"+so, "com0com", CNCB)

	opts = append(opts,
		"--create-filter=escparse,com,parse",
		"--create-filter=pinmap,com,pinmap:--rts=cts --dtr=dsr",
		"--create-filter=linectl,com,lc:--br=local --lc=local",
		"--add-filters=0:com",

		"--create-filter=telnet,tcp,telnet:--comport=client",
		"--create-filter=pinmap,tcp,pinmap:--rts=cts --dtr=dsr --break=break",
		"--create-filter=linectl,tcp,lc:--br=remote --lc=remote",
	)
	if crypt != "" {
		opts = append(opts, crypt)
	}
	hub = exec.Command(hub4com, append(opts,
		"--add-filters=1:tcp",

		// "--use-driver=serial",
		"--octs=off",
		"--ito="+ITO,
		"--ox="+XO,
		"--ix="+XO,
		"--write-limit="+LIMIT,
		CNCB,

		"--use-driver=tcp",
		net.JoinHostPort(hphp[0], hphp[1]),
	)...)

	var bBuffer bytes.Buffer
	hub.Stdout = &bBuffer
	hub.Stderr = &bBuffer
	go func() {
		li.Println(cmd("Run", hub))
		err = srcError(hub.Run())
		PrintOk(cmd("Close", hub), err)
		if err != nil {
			closer.Close()
		}
	}()
	for i := 0; i < 24; i++ {
		s, er := bBuffer.ReadString('\n')
		if er == nil {
			if strings.Contains(s, "ERROR") {
				err = Errorf(s)
				return
			}
			fmt.Print(s)
			if s == "TCP(1): Connected\n" {
				break
			}
		}
		time.Sleep(time.Millisecond * 50)
	}
	// fmt.Print(bBuffer.String())
	bBuffer.WriteTo(os.Stdout)
	hub.Stdout = os.Stdout
	hub.Stderr = os.Stderr

	for {
		if baud != "" {
			opts = []string{
				"-sercfg",
				baud,
				"-serial",
				"COM" + sep,
			}
			PrintOk("cmdFromClipBoard", command())
			ki := exec.Command(kitty, opts...)

			li.Println(cmd("Run", ki))
			err = srcError(ki.Run())
			PrintOk(cmd("Close", ki), err)
		}
		menu := wmenu.NewMenu("Choose baud and seconds delay for Ctrl-F2 or commands from clipboard case delay>" + DELAY +
			"\nВыбери скорость и задержку в секундах для Ctrl-F2 или команд из буфера обмена если задержка>" + DELAY)
		menu.Action(func(opts []wmenu.Opt) error {
			for _, o := range opts {
				if strings.HasPrefix(o.Text, "0") {
					commandDelay = o.Text
				} else {
					baud = o.Text
				}
			}
			li.Println("baud", baud)
			li.Println("commandDelay", commandDelay)
			return nil
		})
		menu.InitialIndex(0)
		ok = false
		menu.Option(tit(DELAY, commandDelay, false))
		menu.Option(tit("115200", baud, false))
		menu.Option(tit("0.2", commandDelay, false))
		menu.Option(tit("38400", baud, false))
		menu.Option(tit("0.4", commandDelay, false))
		menu.Option(tit("57600", baud, false))
		menu.Option(tit("0.6", commandDelay, false))
		menu.Option(tit("0.7", commandDelay, false))
		menu.Option(tit("0.08", commandDelay, false))
		menu.Option(tit("9600", baud, baud == ""))

		if !ok {
			// menu.Option(baud, 10, true, nil)
			menu.Option(tit(baud, baud, false))
		}
		if menu.Run() != nil {
			return
		}
	}
	// closer.Hold()
}

func tit(t, def string, or bool) (title string, value interface{}, isDefault bool, function func(wmenu.Opt) error) {
	isDefault = t == def || or
	ok = ok || isDefault
	return t, 0, isDefault, nil
}

func SetValue(section *ini.Section, key, val string) (set bool) {
	set = section.Key(key).String() != val
	if set {
		ltf.Println(key, val)
		section.Key(key).SetValue(val)
	}
	return
}

func command() error {
	ini.PrettyFormat = false
	iniFile, err := ini.LoadSources(ini.LoadOptions{
		IgnoreInlineComment: false,
	}, kittyINI)
	if err != nil {
		return err
	}
	section := iniFile.Section("KiTTY")
	ok := SetValue(section, "commanddelay", commandDelay)
	if ok {
		err = iniFile.SaveTo(kittyINI)
		if err != nil {
			return err
		}
	}
	if commandDelay == DELAY {
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
	opts = append(opts,
		"-cmd",
		clip,
	)
	return nil
}
