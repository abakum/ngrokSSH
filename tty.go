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
	"gopkg.in/ini.v1"
)

const (
	KITTYINI = "kitty.ini"
)

var (
	commandDelay = DELAY
	ok           bool
	opts         []string
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
	PrintOk(cmd("Start", Hub), Hub.Start())
	// go func() {
	// 	li.Println(cmd("Run", Hub))
	// 	PrintOk(cmd("Close", Hub), Hub.Run())
	// }()
	defer kill()
	for i := 0; i < 24; i++ {
		s, er := bBuffer.ReadString('\n')
		if er == nil {
			if strings.Contains(s, "ERROR") {
				Err = Errorf(s)
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
	Hub.Stdout = os.Stdout
	Hub.Stderr = os.Stderr

	for {
		if Baud != "" {
			opts = []string{
				"-sercfg",
				Baud,
				"-serial",
				"COM" + So,
			}
			PrintOk("cmdFromClipBoard", command())
			ki := exec.Command(Fns[KITTY], opts...)

			li.Println(cmd("Run", ki))
			Err = srcError(ki.Run())
			PrintOk(cmd("Close", ki), Err)
		}
		menu := wmenu.NewMenu("Choose baud and seconds delay for Ctrl-F2 or commands from clipboard case delay>" + DELAY +
			"\nВыбери скорость и задержку в секундах для Ctrl-F2 или команд из буфера обмена если задержка>" + DELAY)
		menu.Action(func(opts []wmenu.Opt) error {
			for _, o := range opts {
				if strings.HasPrefix(o.Text, "0") {
					commandDelay = o.Text
				} else {
					Baud = o.Text
				}
			}
			li.Println("baud", Baud)
			li.Println("commandDelay", commandDelay)
			return nil
		})
		menu.InitialIndex(0)
		ok = false
		menu.Option(tit(DELAY, commandDelay, false))
		menu.Option(tit("115200", Baud, false))
		menu.Option(tit("0.2", commandDelay, false))
		menu.Option(tit("38400", Baud, false))
		menu.Option(tit("0.4", commandDelay, false))
		menu.Option(tit("57600", Baud, false))
		menu.Option(tit("0.6", commandDelay, false))
		menu.Option(tit("0.7", commandDelay, false))
		menu.Option(tit("0.08", commandDelay, false))
		menu.Option(tit("9600", Baud, Baud == ""))

		if !ok {
			// menu.Option(baud, 10, true, nil)
			menu.Option(tit(Baud, Baud, false))
		}
		if menu.Run() != nil {
			return
		}
	}
	// closer.Hold()
}

func kill() {
	if Hub.Process != nil {
		PrintOk(cmd("Kill", Hub), Hub.Process.Kill())
		// time.Sleep(time.Second)
	}
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
	}, Fns[KITTYINI])
	if err != nil {
		return err
	}
	section := iniFile.Section("KiTTY")
	ok := SetValue(section, "commanddelay", commandDelay)
	if ok {
		err = iniFile.SaveTo(Fns[KITTYINI])
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
