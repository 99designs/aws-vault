package prompt

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func OSAScriptMfaPrompt(mfaSerial string) (string, error) {
	if !validateMfaName(mfaSerial) {
		return "", errors.New(fmt.Sprintf("Invalid Mfa serial name %s.", mfaSerial))
	}
	cmd := exec.Command("osascript", "-e", fmt.Sprintf(`
		display dialog "%s" default answer "" buttons {"OK", "Cancel"} default button 1
        text returned of the result
        return result`,
		mfaPromptMessage(mfaSerial)))

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	Methods["osascript"] = OSAScriptMfaPrompt
}
