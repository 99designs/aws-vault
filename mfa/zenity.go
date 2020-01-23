package mfa

import (
	"fmt"
	"os/exec"
	"strings"
)

func init() {
	TokenProviders["zenity"] = Zenity{}
}

type Zenity struct{}

func (z Zenity) Retrieve(mfaSerial string) (string, error) {
	cmd := exec.Command("zenity", "--entry", "--title=aws-vault", fmt.Sprintf(`--text=%s`, defaultPrompt(mfaSerial)))

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}
