package prompt

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// YkmanProvider runs ykman to generate a OATH-TOTP token from the Yubikey device
// To set up ykman, first run `ykman oath add`
func YkmanMfaProvider(mfaSerial string) (string, error) {
	yubikeyOathCredName := os.Getenv("YKMAN_OATH_CREDENTIAL_NAME")
	if yubikeyOathCredName == "" {
		yubikeyOathCredName = mfaSerial
	}

	log.Printf("Fetching MFA code using `ykman oath code --single %s`", yubikeyOathCredName)
	cmd := exec.Command("ykman", "oath", "code", "--single", yubikeyOathCredName)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ykman: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	Methods["ykman"] = YkmanMfaProvider
}
