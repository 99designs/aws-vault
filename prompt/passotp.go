package prompt

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// PassOTPProvider uses the pass otp extension to generate a OATH-TOTP token
// To set up pass otp, first create a pass otp credential with a name of your
// mfaSerial, or set PASS_OATH_CREDENTIAL_NAME.
func PassMfaProvider(mfaSerial string) (string, error) {
	passOathCredName := os.Getenv("PASS_OATH_CREDENTIAL_NAME")
	if passOathCredName == "" {
		passOathCredName = mfaSerial
	}

	log.Printf("Fetching MFA code using `pass otp %s`", passOathCredName)
	cmd := exec.Command("pass", "otp", passOathCredName)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("pass: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	Methods["pass"] = PassMfaProvider
}
