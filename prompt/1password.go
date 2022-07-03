package prompt

import (
    "fmt"
    "os"
    "os/exec"
    "strings"
)

func OnePasswordPrompt(mfaSerial string) (string, error) {
    opTagName := os.Getenv("AWS_VAULT_OP_TAG_NAME")
    if opTagName == "" {
        opTagName = "AWS Vault"
    }

    cmd := exec.Command("sh", "-c", fmt.Sprintf(`
        op item list --tags "%s" --format json | jq -c '[ .[] | select(.urls[] | select(.href == "%s")) ]' | op item get - --otp
    `, opTagName, mfaSerial))

    out, err := cmd.Output()
    if err != nil {
        return "", err
    }

    return strings.TrimSpace(string(out)), nil
}

func init() {
    Methods["1password"] = OnePasswordPrompt
}
