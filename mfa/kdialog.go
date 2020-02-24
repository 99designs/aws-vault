package mfa

import (
	"os/exec"
	"strings"
)

func init() {
	TokenProviders["kdialog"] = &KDialog{}
}

type KDialog struct {
	Serial string
}

func (k *KDialog) GetToken() (string, error) {
	cmd := exec.Command("kdialog", "--inputbox", defaultPrompt(k.Serial), "--title", "aws-vault")

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func (k *KDialog) SetSerial(mfaSerial string) {
	k.Serial = mfaSerial
}

func (k *KDialog) GetSerial() string {
	return k.Serial
}
