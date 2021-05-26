package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

func TerminalPrompt(message string) (string, error) {
	fmt.Fprint(os.Stderr, message)

	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(text), nil
}

func TerminalSecretPrompt(message string) (string, error) {
	fmt.Fprint(os.Stderr, message)

	text, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}

	fmt.Println()

	return strings.TrimSpace(string(text)), nil
}

func TerminalMfaPrompt(mfaSerial string) (string, error) {
	return TerminalPrompt(mfaPromptMessage(mfaSerial))
}

func init() {
	Methods["terminal"] = TerminalMfaPrompt
}
