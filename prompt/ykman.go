package prompt

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/blang/semver"
)

// YkmanProvider runs ykman to generate a OATH-TOTP token from the Yubikey device
// To set up ykman, first run `ykman oath add`
func YkmanMfaProvider(mfaSerial string) (string, error) {
	yubikeyOathCredName := os.Getenv("YKMAN_OATH_CREDENTIAL_NAME")
	if yubikeyOathCredName == "" {
		yubikeyOathCredName = mfaSerial
	}

	// Yubikey Manager v4 replaced ykman oauth code with ykman oath accounts code
	versionCmd := exec.Command("ykman", "--version")
	versionOut, err := versionCmd.Output()
	if err != nil {
		return "", fmt.Errorf("ykman: %w", err)
	}
	versionRegex := regexp.MustCompile(`^YubiKey Manager \(ykman\) version: (\d+\.\d+\.\d+)`)
	version := versionRegex.FindStringSubmatch(string(versionOut))
	log.Printf("ykman version: %s", version[1])
	ykmanVersion, _ := semver.ParseTolerant(version[1])
	v4, _ := semver.Make("4.0.0")
	var ykmanArgs []string
	if ykmanVersion.GTE(v4) {
		ykmanArgs = []string{"oath", "accounts", "code", "--single", yubikeyOathCredName}
	} else {
		ykmanArgs = []string{"oath", "code", "--single", yubikeyOathCredName}
	}

	log.Printf("Fetching MFA code using `ykman %v`", strings.Join(ykmanArgs, " "))
	cmd := exec.Command("ykman", ykmanArgs...)
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
