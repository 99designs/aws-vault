package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func TerminalPrompt(mfaSerial string) (string, error) {
	fmt.Fprint(os.Stderr, mfaPromptMessage(mfaSerial))

	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(text), nil
}

func init() {
	Methods["terminal"] = TerminalPrompt
}
