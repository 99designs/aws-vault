package vault

import (
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"

	"github.com/99designs/aws-vault/mfa"
)

// SessionTokenProvider retrieves temporary credentials from STS using GetSessionToken
type SessionTokenProvider struct {
	StsClient     *sts.STS
	Duration      time.Duration
	ExpiryWindow  time.Duration
	TokenProvider mfa.TokenProvider
	credentials.Expiry
}

// Retrieve generates a new set of temporary credentials using STS GetSessionToken
func (p *SessionTokenProvider) Retrieve() (credentials.Value, error) {
	session, err := p.GetSessionToken()
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(*session.Expiration, p.ExpiryWindow)
	return credentials.Value{
		AccessKeyID:     *session.AccessKeyId,
		SecretAccessKey: *session.SecretAccessKey,
		SessionToken:    *session.SessionToken,
	}, nil
}

// GetSessionToken generates a new set of temporary credentials using STS GetSessionToken
func (p *SessionTokenProvider) GetSessionToken() (*sts.Credentials, error) {
	var err error

	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(p.Duration.Seconds())),
	}

	mfaSerial := p.TokenProvider.GetSerial()
	if mfaSerial != "" {
		input.SerialNumber = aws.String(mfaSerial)
		tokenCode, err := p.TokenProvider.GetToken()
		if err != nil {
			return nil, err
		}
		input.TokenCode = aws.String(tokenCode)
	}

	resp, err := p.StsClient.GetSessionToken(input)
	if err != nil {
		return nil, err
	}

	log.Printf("Generated credentials %s using GetSessionToken, expires in %s", FormatKeyForDisplay(*resp.Credentials.AccessKeyId), time.Until(*resp.Credentials.Expiration).String())

	return resp.Credentials, nil
}
