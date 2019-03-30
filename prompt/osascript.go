package prompt

import (
	"fmt"
	"os/exec"
	"strings"
)

func OSAScriptPrompt(prompt string, _profile string) (string, error) {
	cmd := exec.Command("osascript", "-e", fmt.Sprintf(`
		display dialog "%s" default answer "" buttons {"OK", "Cancel"} default button 1
        text returned of the result
        return result`,
		prompt))

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	Methods["osascript"] = OSAScriptPrompt
}
