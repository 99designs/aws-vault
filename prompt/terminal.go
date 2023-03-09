package prompt

import (
	"fmt"
	"strings"

	"github.com/mattn/go-tty"
)

func TerminalPrompt(message string) (string, error) {
	tty, err := tty.Open()
	if err != nil {
		return "", err
	}
	defer tty.Close()

	fmt.Fprint(tty.Output(), message)

	text, err := tty.ReadString()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(text), nil
}

func TerminalSecretPrompt(message string) (string, error) {
	tty, err := tty.Open()
	if err != nil {
		return "", err
	}
	defer tty.Close()

	fmt.Fprint(tty.Output(), message)

	text, err := tty.ReadPassword()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(text)), nil
}

func TerminalMfaPrompt(mfaSerial string) (string, error) {
	return TerminalPrompt(mfaPromptMessage(mfaSerial))
}

func init() {
	Methods["terminal"] = TerminalMfaPrompt
}
