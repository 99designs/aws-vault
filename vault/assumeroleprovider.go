package vault

import (
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
)

// AssumeRoleProvider retrieves temporary credentials from STS using AssumeRole
type AssumeRoleProvider struct {
	StsClient       *sts.STS
	RoleARN         string
	RoleSessionName string
	ExternalID      string
	Duration        time.Duration
	ExpiryWindow    time.Duration
	Mfa
	credentials.Expiry
}

// Retrieve generates a new set of temporary credentials using STS AssumeRole
func (p *AssumeRoleProvider) Retrieve() (credentials.Value, error) {
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

func (p *AssumeRoleProvider) roleSessionName() string {
	if p.RoleSessionName == "" {
		// Try to work out a role name that will hopefully end up unique.
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}

	return p.RoleSessionName
}

func (p *AssumeRoleProvider) assumeRole() (*sts.Credentials, error) {
	var err error

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(p.RoleARN),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int64(int64(p.Duration.Seconds())),
	}

	if p.ExternalID != "" {
		input.ExternalId = aws.String(p.ExternalID)
	}

	if p.MfaSerial != "" {
		input.SerialNumber = aws.String(p.MfaSerial)
		input.TokenCode, err = p.GetMfaToken()
		if err != nil {
			return nil, err
		}
	}

	log.Printf("Using STS endpoint %s", p.StsClient.Endpoint)

	resp, err := p.StsClient.AssumeRole(input)
	if err != nil {
		return nil, err
	}

	log.Printf("Generated credentials %s using AssumeRole, expires in %s", FormatKeyForDisplay(*resp.Credentials.AccessKeyId), time.Until(*resp.Credentials.Expiration).String())

	return resp.Credentials, nil
}
