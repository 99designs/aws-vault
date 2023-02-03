package vault

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// AssumeRoleProvider retrieves temporary credentials from STS using AssumeRole
type AssumeRoleProvider struct {
	StsClient         *sts.Client
	RoleARN           string
	RoleSessionName   string
	ExternalID        string
	Duration          time.Duration
	Tags              map[string]string
	TransitiveTagKeys []string
	SourceIdentity    string
	*Mfa
}

// Retrieve generates a new set of temporary credentials using STS AssumeRole
func (p *AssumeRoleProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	role, err := p.assumeRole(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	return aws.Credentials{
		AccessKeyID:     *role.AccessKeyId,
		SecretAccessKey: *role.SecretAccessKey,
		SessionToken:    *role.SessionToken,
		CanExpire:       true,
		Expires:         *role.Expiration,
	}, nil
}

func (p *AssumeRoleProvider) roleSessionName() string {
	if p.RoleSessionName == "" {
		// Try to work out a role name that will hopefully end up unique.
		return fmt.Sprintf("%d", time.Now().UTC().UnixNano())
	}

	return p.RoleSessionName
}

func (p *AssumeRoleProvider) assumeRole(ctx context.Context) (*ststypes.Credentials, error) {
	var err error

	input := &sts.AssumeRoleInput{
		RoleArn:         aws.String(p.RoleARN),
		RoleSessionName: aws.String(p.roleSessionName()),
		DurationSeconds: aws.Int32(int32(p.Duration.Seconds())),
	}

	if p.ExternalID != "" {
		input.ExternalId = aws.String(p.ExternalID)
	}

	if p.GetMfaSerial() != "" {
		input.SerialNumber = aws.String(p.GetMfaSerial())
		input.TokenCode, err = p.GetMfaToken()
		if err != nil {
			return nil, err
		}
	}

	if len(p.Tags) > 0 {
		input.Tags = make([]ststypes.Tag, 0)
		for key, value := range p.Tags {
			tag := ststypes.Tag{
				Key:   aws.String(key),
				Value: aws.String(value),
			}
			input.Tags = append(input.Tags, tag)
		}
	}

	if len(p.TransitiveTagKeys) > 0 {
		input.TransitiveTagKeys = p.TransitiveTagKeys
	}

	if p.SourceIdentity != "" {
		input.SourceIdentity = aws.String(p.SourceIdentity)
	}

	resp, err := p.StsClient.AssumeRole(ctx, input)
	if err != nil {
		return nil, err
	}

	log.Printf("Generated credentials %s using AssumeRole, expires in %s", FormatKeyForDisplay(*resp.Credentials.AccessKeyId), time.Until(*resp.Credentials.Expiration).String())

	return resp.Credentials, nil
}
