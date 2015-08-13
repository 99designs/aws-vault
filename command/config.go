package command

import "os"

func ProfileFromEnv() string {
	if p := os.Getenv("AWS_VAULT_PROFILE"); p != "" {
		return p
	}
	if p := os.Getenv("AWS_DEFAULT_PROFILE"); p != "" {
		return p
	}
	return "default"
}
