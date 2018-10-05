package prompt

import (
	"fmt"
	"os/exec"
	"strings"
)

func ZenityPrompt(prompt string) (string, error) {
	cmd := exec.Command("zenity", "--entry", "--title=aws-vault", fmt.Sprintf(`--text=%s`, prompt))

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	Methods["zenity"] = ZenityPrompt
}
