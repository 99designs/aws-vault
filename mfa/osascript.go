package mfa

import (
	"fmt"
	"os/exec"
	"strings"
)

func init() {
	TokenProviders["osascript"] = OsaScript{}
}

type OsaScript struct{}

func (o OsaScript) Retrieve(mfaSerial string) (string, error) {
	cmd := exec.Command("osascript", "-e", fmt.Sprintf(`
		display dialog "%s" default answer "" buttons {"OK", "Cancel"} default button 1
        text returned of the result
        return result`,
		defaultPrompt(mfaSerial)))

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}
