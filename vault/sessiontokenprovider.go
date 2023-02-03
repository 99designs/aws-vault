package vault

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

// SessionTokenProvider retrieves temporary credentials from STS using GetSessionToken
type SessionTokenProvider struct {
	StsClient *sts.Client
	Duration  time.Duration
	*Mfa
}

// Retrieve generates a new set of temporary credentials using STS GetSessionToken
func (p *SessionTokenProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := p.GetSessionToken(ctx)
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

// GetSessionToken generates a new set of temporary credentials using STS GetSessionToken
func (p *SessionTokenProvider) GetSessionToken(ctx context.Context) (*ststypes.Credentials, error) {
	var err error

	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int32(int32(p.Duration.Seconds())),
	}

	if p.GetMfaSerial() != "" {
		input.SerialNumber = aws.String(p.GetMfaSerial())
		input.TokenCode, err = p.GetMfaToken()
		if err != nil {
			return nil, err
		}
	}

	resp, err := p.StsClient.GetSessionToken(ctx, input)
	if err != nil {
		return nil, err
	}

	log.Printf("Generated credentials %s using GetSessionToken, expires in %s", FormatKeyForDisplay(*resp.Credentials.AccessKeyId), time.Until(*resp.Credentials.Expiration).String())

	return resp.Credentials, nil
}
