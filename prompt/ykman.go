package prompt

import (
	"fmt"
	"os/exec"
	"strings"
)

// YkmanProvider runs ykman to generate a OATH-TOTP token from the Yubikey device
// To set up ykman, first run `ykman oath add`
func YkmanProvider(mfaSerial string) (string, error) {
	cmd := exec.Command("ykman", "oath", "code", "-s", mfaSerial)

	out, err := cmd.Output()
	if err != nil {
		stderr := ""
		if ee, ok := err.(*exec.ExitError); ok && len(ee.Stderr) > 0 {
			stderr = ":\n" + string(ee.Stderr)
		}
		return "", fmt.Errorf("ykman: %w%s", err, stderr)
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	Methods["ykman"] = YkmanProvider
}
