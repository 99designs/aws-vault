package prompt

import (
	"fmt"
	"os/exec"
	"strings"
)

func OSAScriptMfaPrompt(mfaSerial string) (string, error) {
	cmd := exec.Command("osascript", "-e", fmt.Sprintf(`
		display dialog %q default answer "" buttons {"OK", "Cancel"} default button 1
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
	if _, err := exec.LookPath("osascript"); err == nil {
		Methods["osascript"] = OSAScriptMfaPrompt
	}
}
