package mfa

import (
	"fmt"
	"os/exec"
	"strings"
)

func init() {
	TokenProviders["osascript"] = &OsaScript{}
}

type OsaScript struct {
	Serial string
}

func (o *OsaScript) GetToken() (string, error) {
	cmd := exec.Command("osascript", "-e", fmt.Sprintf(`
		display dialog "%s" default answer "" buttons {"OK", "Cancel"} default button 1
        text returned of the result
        return result`,
		defaultPrompt(o.Serial)))

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func (o *OsaScript) SetSerial(mfaSerial string) {
	o.Serial = mfaSerial
}

func (o *OsaScript) GetSerial() string {
	return o.Serial
}
