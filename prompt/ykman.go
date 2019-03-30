package prompt

import (
	"os/exec"
	"strings"
)

func YkmanPrompt(_prompt string, profile string) (string, error) {
	cmd := exec.Command("ykman", "oath", "code", profile)
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	parts := strings.Split(string(out), " ")
	return parts[len(parts)-1], nil
}
