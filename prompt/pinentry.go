package prompt

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// PinentryMfaPrompt uses GnuPG's pinentry program to prompt
// for an OATH-TOTP token. Looks for a program in PATH named "pinentry",
// unless the AWS_VAULT_PINENTRY_PROGRAM environment variable is set.
func PinentryMfaPrompt(mfaSerial string) (string, error) {
	cmdName := os.Getenv("AWS_VAULT_PINENTRY_PROGRAM")
	if cmdName == "" {
		cmdName = "pinentry"
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := exec.CommandContext(ctx, cmdName)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return "", err
	}

	br := bufio.NewReader(stdout)
	sendReceive := func(s ...string) ([]byte, error) {
		if len(s) > 0 {
			fmt.Fprint(stdin, strings.Join(s, " ")+"\n")
		}
		line, _, err := br.ReadLine()
		if err != nil {
			return nil, fmt.Errorf("pinentry: %w", err)
		}
		if !(bytes.HasPrefix(line, []byte("OK")) || bytes.HasPrefix(line, []byte("D "))) {
			return nil, fmt.Errorf("pinentry response: %q", line)
		}
		return line, nil
	}

	// First line from pinentry should be a welcome message starting with "OK".
	if _, err := sendReceive(); err != nil {
		return "", err
	}

	_, _ = sendReceive("OPTION", "display="+os.Getenv("DISPLAY"))
	_, _ = sendReceive("OPTION", "ttytype="+os.Getenv("TERM"))
	if tty, err := os.Readlink("/proc/self/fd/0"); err == nil {
		_, _ = sendReceive("OPTION", "ttyname="+tty)
	}
	if _, err := sendReceive("SETTITLE", ""); err != nil {
		return "", err
	}
	if _, err := sendReceive("SETPROMPT", ""); err != nil {
		return "", err
	}
	if _, err := sendReceive("SETPROMPT", strings.TrimSuffix(mfaPromptMessage(mfaSerial), ": ")); err != nil {
		return "", err
	}

	line, err := sendReceive("GETPIN")
	if err != nil {
		return "", err
	}
	line = line[2:] // Response starts with "D ".
	return string(bytes.TrimSpace(line)), nil
}

func init() {
	Methods["pinentry"] = PinentryMfaPrompt
}
