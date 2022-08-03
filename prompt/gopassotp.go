package prompt

import (
	"fmt"
	"log"
	"os"
	"strings"

	exec "golang.org/x/sys/execabs"
)

// GoPassOTPProvider uses the gopass otp extension to generate a OATH-TOTP token
// To set up gopass otp, first create a gopass otp credential with a name of your
// mfaSerial, or set PASS_OATH_CREDENTIAL_NAME.
func GoPassMfaProvider(mfaSerial string) (string, error) {
	passOathCredName := os.Getenv("PASS_OATH_CREDENTIAL_NAME")
	if passOathCredName == "" {
		passOathCredName = mfaSerial
	}

	log.Printf("Fetching MFA code using `gopass otp -o %s`", passOathCredName)
	cmd := exec.Command("gopass", "otp", "-o", passOathCredName)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("pass: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	Methods["gopass"] = GoPassMfaProvider
}
