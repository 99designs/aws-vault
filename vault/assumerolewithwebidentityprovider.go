package vault

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
)

// AssumeRoleWithWebIdentityProvider retrieves temporary credentials from STS using AssumeRoleWithWebIdentity
type AssumeRoleWithWebIdentityProvider struct {
	StsClient               *sts.STS
	RoleARN                 string
	RoleSessionName         string
	WebIdentityTokenFile    string
	WebIdentityTokenProcess string
	ExternalID              string
	Duration                time.Duration
	ExpiryWindow            time.Duration
	credentials.Expiry
}

// Retrieve generates a new set of temporary credentials using STS AssumeRoleWithWebIdentity
func (p *AssumeRoleWithWebIdentityProvider) Retrieve() (credentials.Value, error) {
	role, err := p.assumeRole()
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(*role.Expiration, p.ExpiryWindow)
	return credentials.Value{
		AccessKeyID:     *role.AccessKeyId,
		SecretAccessKey: *role.SecretAccessKey,
		SessionToken:    *role.SessionToken,
	}, nil
}

func (p *AssumeRoleWithWebIdentityProvider) roleSessionName() string {
	if p.RoleSessionName == "" {
		// Try to work out a role name that will hopefully end up unique.
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}

	return p.RoleSessionName
}

func (p *AssumeRoleWithWebIdentityProvider) assumeRole() (*sts.Credentials, error) {
	var err error

	webIdentityToken, err := p.webIdentityToken()
	if err != nil {
		return nil, err
	}

	req, resp := p.StsClient.AssumeRoleWithWebIdentityRequest(&sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(p.RoleARN),
		RoleSessionName:  aws.String(p.roleSessionName()),
		DurationSeconds:  aws.Int64(int64(p.Duration.Seconds())),
		WebIdentityToken: aws.String(webIdentityToken),
	})
	// Retry possibly temporary errors
	req.RetryErrorCodes = append(req.RetryErrorCodes, sts.ErrCodeInvalidIdentityTokenException)

	if err := req.Send(); err != nil {
		return nil, err
	}

	log.Printf("Generated credentials %s using AssumeRoleWithWebIdentity, expires in %s", FormatKeyForDisplay(*resp.Credentials.AccessKeyId), time.Until(*resp.Credentials.Expiration).String())

	return resp.Credentials, nil
}

func (p *AssumeRoleWithWebIdentityProvider) webIdentityToken() (string, error) {
	// Read OpenID Connect token from WebIdentityTokenFile
	if p.WebIdentityTokenFile != "" {
		b, err := ioutil.ReadFile(p.WebIdentityTokenFile)
		if err != nil {
			return "", fmt.Errorf("unable to read file at %s: %v", p.WebIdentityTokenFile, err)
		}

		return string(b), nil
	}

	// Exec WebIdentityTokenProcess to retrieve OpenID Connect token
	var cmdArgs []string
	if runtime.GOOS == "windows" {
		cmdArgs = []string{"cmd.exe", "/C", p.WebIdentityTokenProcess}
	} else {
		cmdArgs = []string{"/bin/sh", "-c", p.WebIdentityTokenProcess}
	}

	cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stderr = os.Stderr

	b, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("failed to run command %q: %v", p.WebIdentityTokenProcess, err)
	}

	return string(b), err
}
