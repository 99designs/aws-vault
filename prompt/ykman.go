package prompt

import (
	"os/exec"
)

func YkmanPrompt(_prompt string, mfa_serial string) (string, error) {
	cmd := exec.Command("ykman", "oath", "code", "-s", mfa_serial)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out[:len(out)-1]), nil
}
