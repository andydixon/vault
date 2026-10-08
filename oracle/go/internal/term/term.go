package term

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"
)

// enableVirtualTerminalProcessing tries to enable virtual terminal processing
// on Windows. If it fails, avoid using escape sequences to prevent weird
// characters being printed to the console.
var enableVirtualTerminalProcessing func(out *os.File) error

// clearLine clears the current line on the terminal, or opens a new line if
// terminal escape codes don't work.
func clearLine(out *os.File) {
	const (
		CUI = "\033["   // Control Sequence Introducer
		CPL = CUI + "F" // Cursor Previous Line
		EL  = CUI + "K" // Erase in Line
	)

	// First, open a new line, which is guaranteed to work everywhere. Then, try
	// to erase the line above with escape codes, if possible.
	//
	// (We use CRLF instead of LF to work around an apparent bug in WSL2's
	// handling of CONOUT$. Only when running a Windows binary from WSL2, the
	// cursor would not go back to the start of the line with a simple LF.
	// Honestly, it's impressive CONIN$ and CONOUT$ work at all inside WSL2.)
	fmt.Fprintf(out, "\r\n")
	if enableVirtualTerminalProcessing == nil || enableVirtualTerminalProcessing(out) == nil {
		fmt.Fprintf(out, CPL+EL)
	}
}

// WithTerminal runs f with the terminal input and output files, if available.
// WithTerminal does not open a non-terminal stdin, so the caller does not need
// to check if stdin is in use.
func WithTerminal(f func(in, out *os.File) error) error {
	if runtime.GOOS == "windows" {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer out.Close()
		return f(in, out)
	} else if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		return f(tty, tty)
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		return f(os.Stdin, os.Stdin)
	} else {
		return fmt.Errorf("standard input is not a terminal, and /dev/tty is not available: %v", err)
	}
}

// ReadSecret reads a value from the terminal with no echo. The prompt is ephemeral.
func ReadSecret(prompt string) (s []byte, err error) {
	err = WithTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer clearLine(out)
		s, err = term.ReadPassword(int(in.Fd()))
		return err
	})
	return
}

// Confirm asks a yes/no question on the terminal. Only "y" or "yes" is yes.
func Confirm(prompt string) (yes bool, err error) {
	err = WithTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && line == "" {
			return err
		}
		switch strings.ToLower(strings.TrimSpace(line)) {
		case "y", "yes":
			yes = true
		}
		return nil
	})
	return
}

// ReadPassphrase returns the passphrase from the environment variable env if
// it is set, otherwise prompts on the terminal.
func ReadPassphrase(prompt, env string) (string, error) {
	if p, ok := os.LookupEnv(env); ok {
		if p == "" {
			return "", fmt.Errorf("%s is set but empty", env)
		}
		return p, nil
	}
	p, err := ReadSecret(prompt)
	if err != nil {
		return "", fmt.Errorf("could not read passphrase (set %s for non-interactive use): %v", env, err)
	}
	return string(p), nil
}
