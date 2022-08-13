package prompt

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"strings"

	exec "golang.org/x/sys/execabs"
)

// onePasswordUrl represents the type of the `urls`
type onePasswordUrl struct {
	Href string `json:"href"`
}

type onePasswordItem struct {
	Id   string            `json:"id"`
	Urls *[]onePasswordUrl `json:"urls"`
}

// OnePasswordMfaProvider runs `op` to generate a OATH-TOTP token from a
// 1password item
func OnePasswordMfaProvider(mfaSerial string) (string, error) {
	acc, err := getAccount(mfaSerial)
	if err != nil {
		return "", err
	}
	if acc == nil {
		return "", fmt.Errorf("no item found in 1Password for %s", mfaSerial)
	}

	log.Println("Retrieving OTP")
	cmd := exec.Command("op", "item", "get", "--otp", acc.Id)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("op: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}

func getAccount(mfaSerial string) (*onePasswordItem, error) {
	onePassTagName := os.Getenv("AWS_VAULT_OP_TAG_NAME")
	if onePassTagName == "" {
		onePassTagName = "aws-vault"
	}

	log.Println("Listing available items in 1password")
	cmd := exec.Command("op", "item", "list", "--format", "json", "--tags", onePassTagName)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("op: %w", err)
	}

	list := []onePasswordItem{}

	err = json.Unmarshal(out, &list)
	if err != nil {
		return nil, fmt.Errorf("op: %w", err)
	}

	for _, item := range list {
		if item.Urls == nil {
			continue
		}

		for _, url := range *item.Urls {
			if url.Href == mfaSerial {
				return &item, nil
			}
		}
	}

	return nil, nil
}

func init() {
	Methods["1password"] = OnePasswordMfaProvider
}
