package prompt

import (
	"os/exec"
	"strings"
)

func YkmanPrompt(_prompt string, mfa_serial string) (string, error) {
	cmd := exec.Command("ykman", "oath", "code", mfa_serial)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(out), " ")
	return parts[len(parts)-1], nil
}
