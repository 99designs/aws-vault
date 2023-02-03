package vault

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// AssumeRoleWithWebIdentityProvider retrieves temporary credentials from STS using AssumeRoleWithWebIdentity
type AssumeRoleWithWebIdentityProvider struct {
	StsClient               *sts.Client
	RoleARN                 string
	RoleSessionName         string
	WebIdentityTokenFile    string
	WebIdentityTokenProcess string
	ExternalID              string
	Duration                time.Duration
}

// Retrieve generates a new set of temporary credentials using STS AssumeRoleWithWebIdentity
func (p *AssumeRoleWithWebIdentityProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
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

func (p *AssumeRoleWithWebIdentityProvider) roleSessionName() string {
	if p.RoleSessionName == "" {
		// Try to work out a role name that will hopefully end up unique.
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}

	return p.RoleSessionName
}

func (p *AssumeRoleWithWebIdentityProvider) assumeRole(ctx context.Context) (*ststypes.Credentials, error) {
	var err error

	webIdentityToken, err := p.webIdentityToken()
	if err != nil {
		return nil, err
	}

	resp, err := p.StsClient.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
		RoleArn:          aws.String(p.RoleARN),
		RoleSessionName:  aws.String(p.roleSessionName()),
		DurationSeconds:  aws.Int32(int32(p.Duration.Seconds())),
		WebIdentityToken: aws.String(webIdentityToken),
	})
	if err != nil {
		return nil, err
	}

	log.Printf("Generated credentials %s using AssumeRoleWithWebIdentity, expires in %s", FormatKeyForDisplay(*resp.Credentials.AccessKeyId), time.Until(*resp.Credentials.Expiration).String())

	return resp.Credentials, nil
}

func (p *AssumeRoleWithWebIdentityProvider) webIdentityToken() (string, error) {
	// Read OpenID Connect token from WebIdentityTokenFile
	if p.WebIdentityTokenFile != "" {
		b, err := os.ReadFile(p.WebIdentityTokenFile)
		if err != nil {
			return "", fmt.Errorf("unable to read file at %s: %v", p.WebIdentityTokenFile, err)
		}

		return string(b), nil
	}

	// Exec WebIdentityTokenProcess to retrieve OpenID Connect token
	return executeProcess(p.WebIdentityTokenProcess)
}
