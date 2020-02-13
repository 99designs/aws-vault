package prompt

import (
	"os/exec"
	"strings"
)

func KDialogPrompt(prompt string) (string, error) {
	cmd := exec.Command("kdialog", "--inputbox", prompt, "--title", "aws-vault")

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	Methods["kdialog"] = KDialogPrompt
}
