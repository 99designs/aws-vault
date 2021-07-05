package prompt

import (
	"fmt"
	"log"
	"os"
	"strings"

	exec "golang.org/x/sys/execabs"
)

// YkmanProvider runs ykman to generate a OATH-TOTP token from the Yubikey device
// To set up ykman, first run `ykman oath add`
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

	ykmanMajorVersion := os.Getenv("AWS_VAULT_YKMAN_VERSION")
	if ykmanMajorVersion == "1" ||
		ykmanMajorVersion == "2" ||
		ykmanMajorVersion == "3" {
		args = append(args, "oath", "code", "--single", yubikeyOathCredName)
	} else { // default to v4 and above
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
	Methods["ykman"] = YkmanMfaProvider
}
