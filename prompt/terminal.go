package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"
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

func TerminalMfaPrompt(mfaSerial string) (string, error) {
	return TerminalPrompt(mfaPromptMessage(mfaSerial))
}

func init() {
	Methods["terminal"] = TerminalMfaPrompt
}
