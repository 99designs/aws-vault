package vault

import (
	"encoding/json"
	"fmt"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"os"
	"os/exec"
	"runtime"
	"time"
)

type CredentialProcessProvider struct {
	CredentialProcess string
	ExpiryWindow      time.Duration
	credentials.Expiry
}

type CredentialProcessResponse struct {
	AccessKeyId     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	SessionToken    string    `json:"SessionToken"`
	Expiration      time.Time `json:"Expiration"`
	Version         int       `json:"Version"`
}

// Retrieve fetch credentials from an external process
func (p *CredentialProcessProvider) Retrieve() (credentials.Value, error) {
	cred, err := p.callCredentialProcess()
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(cred.Expiration, p.ExpiryWindow)
	return credentials.Value{
		AccessKeyID:     cred.AccessKeyId,
		SecretAccessKey: cred.SecretAccessKey,
		SessionToken:    cred.SessionToken,
	}, nil
}

func (p *CredentialProcessProvider) callCredentialProcess() (CredentialProcessResponse, error) {
	var cmdArgs []string
	if runtime.GOOS == "windows" {
		cmdArgs = []string{"cmd.exe", "/C", p.CredentialProcess}
	} else {
		cmdArgs = []string{"/bin/sh", "-c", p.CredentialProcess}
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr

	b, err := cmd.Output()
	if err != nil {
		return CredentialProcessResponse{}, fmt.Errorf("failed to run command %q: %v", p.CredentialProcess, err)
	}
	var cred CredentialProcessResponse
	err = json.Unmarshal(b, &cred)
	if err != nil {
		return CredentialProcessResponse{}, err
	}
	return cred, nil
}
