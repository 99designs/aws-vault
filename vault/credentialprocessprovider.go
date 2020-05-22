package vault

import (
	"encoding/json"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"os/exec"
	"strings"
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
	params := strings.Split(p.CredentialProcess, " ")
	cmd := exec.Command(params[0], params[1:]...)
	out, err := cmd.Output()
	if err != nil {
		return CredentialProcessResponse{}, err
	}
	var cred CredentialProcessResponse
	err = json.Unmarshal(out, &cred)
	if err != nil {
		return CredentialProcessResponse{}, err
	}
	return cred, nil
}
