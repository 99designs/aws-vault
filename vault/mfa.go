package vault

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/99designs/aws-vault/v7/prompt"
	"github.com/aws/aws-sdk-go-v2/aws"
)

// Mfa contains options for an MFA device
type Mfa struct {
	MfaSerial     string
	mfaPromptFunc prompt.Func
}

// GetMfaToken returns the MFA token
func (m Mfa) GetMfaToken() (*string, error) {
	if m.mfaPromptFunc != nil {
		token, err := m.mfaPromptFunc(m.MfaSerial)
		return aws.String(token), err
	}

	return nil, errors.New("No prompt found")
}

func NewMfa(config *ProfileConfig) Mfa {
	m := Mfa{
		MfaSerial: config.MfaSerial,
	}
	if config.MfaToken != "" {
		m.mfaPromptFunc = func(_ string) (string, error) { return config.MfaToken, nil }
	} else if config.MfaProcess != "" {
		m.mfaPromptFunc = func(_ string) (string, error) {
			log.Println("Executing mfa_process")
			return ProcessMfaProvider(config.MfaProcess)
		}
	} else {
		m.mfaPromptFunc = prompt.Method(config.MfaPromptMethod)
	}

	return m
}

func ProcessMfaProvider(processCmd string) (string, error) {
	cmd := exec.Command("/bin/sh", "-c", processCmd)
	cmd.Stderr = os.Stderr

	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("process provider: %w", err)
	}

	return strings.TrimSpace(string(out)), nil
}
