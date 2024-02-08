//go:build windows
// +build windows

package windowsconsole

import (
	"io"
	"os"

	ansiterm "github.com/abakum/go-ansiterm"
	"github.com/abakum/go-ansiterm/winterm"
)

// ansiWriter wraps a standard output file (e.g., os.Stdout) providing ANSI sequence translation.
type ansiWriter struct {
	file           *os.File
	fd             uintptr
	infoReset      *winterm.CONSOLE_SCREEN_BUFFER_INFO
	command        []byte
	escapeSequence []byte
	inAnsiSequence bool
	parser         *ansiterm.AnsiParser
}

// NewAnsiWriter returns an io.Writer that provides VT100 terminal emulation on top of a
// Windows console output handle.
func NewAnsiWriter(nFile int) io.Writer {
	file, _ := winterm.GetStdFile(nFile)
	return NewAnsiWriterFile(file)
}

func NewAnsiWriterFile(src *os.File) io.Writer {
	fd := src.Fd()
	info, err := winterm.GetConsoleScreenBufferInfo(fd)
	if err != nil {
		return nil
	}

	parser := ansiterm.CreateParser("Ground", winterm.CreateWinEventHandler(fd, src), ansiterm.WithFe(true))

	return &ansiWriter{
		file:           src,
		fd:             fd,
		infoReset:      info,
		command:        make([]byte, 0, ansiterm.ANSI_MAX_CMD_LENGTH),
		escapeSequence: []byte(ansiterm.KEY_ESC_CSI),
		parser:         parser,
	}
}

func NewAnsiWriterFileDuplicate(src *os.File) (io.Writer, *os.File, error) {
	duplicate, err := DuplicateFile(src)
	if err != nil {
		return nil, nil, err
	}
	return NewAnsiWriterFile(duplicate), duplicate, nil
}

func (aw *ansiWriter) Fd() uintptr {
	return aw.fd
}

// Write writes len(p) bytes from p to the underlying data stream.
func (aw *ansiWriter) Write(p []byte) (total int, err error) {
	if len(p) == 0 {
		return 0, nil
	}

	return aw.parser.Parse(p)
}
