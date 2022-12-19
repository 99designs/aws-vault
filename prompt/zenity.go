package prompt

import (
	"os/exec"
	"strings"
)

func ZenityMfaPrompt(mfaSerial string) (string, error) {
	cmd := exec.Command("zenity", "--entry", "--title", "aws-vault", "--text", mfaPromptMessage(mfaSerial))

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	Methods["zenity"] = ZenityMfaPrompt
}
