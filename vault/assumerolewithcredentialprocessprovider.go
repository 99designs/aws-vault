package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// CredentialFromProcessProvider retrieves credentials by running aws_vault_credential_process
type CredentialFromProcessProvider struct {
	StsClient                 *sts.Client
	RoleARN                   string
	AWSVaultCredentialProcess string
	Duration                  time.Duration
}

// Retrieve generates a new set of credentials using the credential provider
func (p *CredentialFromProcessProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := p.assumeRole(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		CanExpire:       true,
		Expires:         aws.ToTime(creds.Expiration),
	}, nil
}

func (p *CredentialFromProcessProvider) assumeRole(ctx context.Context) (*ststypes.Credentials, error) {
	var err error

	output, err := p.runCredentialProcess()
	if err != nil {
		return nil, err
	}
	var creds ststypes.Credentials
	err = json.Unmarshal(output, &creds)

	if err != nil {
		return nil, fmt.Errorf("failed to prase credential process output: %v", err)
	}

	return &creds, nil
}

// Execute AWSVaultCredentialProcess to retrieve credentials
func (p *CredentialFromProcessProvider) runCredentialProcess() ([]byte, error) {
	var cmdArgs []string
	if runtime.GOOS == "windows" {
		cmdArgs = []string{"cmd.exe", "/C", p.AWSVaultCredentialProcess}
	} else {
		cmdArgs = []string{"/bin/sh", "-c", p.AWSVaultCredentialProcess}
	}

	log.Printf("Executing credential process %q", p.AWSVaultCredentialProcess)
	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr

	b, err := cmd.Output()
	if err != nil {
		return []byte{}, fmt.Errorf("failed to run command %q: %v", p.AWSVaultCredentialProcess, err)
	}

	return b, err
}
