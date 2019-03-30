package prompt

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func TerminalPrompt(prompt string, _profile string) (string, error) {
	fmt.Fprint(os.Stderr, prompt)

	reader := bufio.NewReader(os.Stdin)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}
