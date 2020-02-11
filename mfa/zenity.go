package mfa

import (
	"fmt"
	"os/exec"
	"strings"
)

func init() {
	TokenProviders["zenity"] = &Zenity{}
}

type Zenity struct {
	Serial string
}

func (z Zenity) GetToken() (string, error) {
	cmd := exec.Command("zenity", "--entry", "--title=aws-vault", fmt.Sprintf(`--text=%s`, defaultPrompt(z.Serial)))

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func (z *Zenity) SetSerial(mfaSerial string) {
	z.Serial = mfaSerial
}

func (z *Zenity) GetSerial() string {
	return z.Serial
}
