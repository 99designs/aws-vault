package prompt

import (
	"strings"

	exec "golang.org/x/sys/execabs"
)

func KDialogMfaPrompt(mfaSerial string) (string, error) {
	cmd := exec.Command("kdialog", "--inputbox", mfaPromptMessage(mfaSerial), "--title", "aws-vault")

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	Methods["kdialog"] = KDialogMfaPrompt
}
