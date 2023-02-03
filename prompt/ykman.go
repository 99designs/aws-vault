package prompt

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

// YkmanProvider runs ykman to generate a OATH-TOTP token from the Yubikey device
// To set up ykman, first run `ykman oath accounts add`
func YkmanMfaProvider(mfaSerial string) (string, error) {
	args := []string{}

	yubikeyOathCredName := os.Getenv("YKMAN_OATH_CREDENTIAL_NAME")
	if yubikeyOathCredName == "" {
		yubikeyOathCredName = mfaSerial
	}

	// Get the serial number of the yubikey device to use.
	yubikeyDeviceSerial := os.Getenv("YKMAN_OATH_DEVICE_SERIAL")
	if yubikeyDeviceSerial != "" {
		// If the env var was set, extend args to support passing the serial.
		args = append(args, "--device", yubikeyDeviceSerial)
	}

	// default to v4 and above
	switch os.Getenv("AWS_VAULT_YKMAN_VERSION") {
	case "1", "2", "3":
		args = append(args, "oath", "code", "--single", yubikeyOathCredName)
	default:
		args = append(args, "oath", "accounts", "code", "--single", yubikeyOathCredName)
	}

	log.Printf("Fetching MFA code using `ykman %s`", strings.Join(args, " "))
	cmd := exec.Command("ykman", args...)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("ykman: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func init() {
	if _, err := exec.LookPath("ykman"); err == nil {
		Methods["ykman"] = YkmanMfaProvider
	}
}
