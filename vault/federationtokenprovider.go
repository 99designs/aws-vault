package vault

import (
	"context"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const allowAllIAMPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

// FederationTokenProvider retrieves temporary credentials from STS using GetFederationToken
type FederationTokenProvider struct {
	StsClient *sts.Client
	Name      string
	Duration  time.Duration
}

func (f *FederationTokenProvider) name() string {
	// truncate the username if it's longer than 32 characters or else GetFederationToken will fail. see: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
	if len(f.Name) > 32 {
		return f.Name[0:32]
	}
	return f.Name
}

// Retrieve generates a new set of temporary credentials using STS GetFederationToken
func (f *FederationTokenProvider) Retrieve(ctx context.Context) (creds aws.Credentials, err error) {
	resp, err := f.StsClient.GetFederationToken(ctx, &sts.GetFederationTokenInput{
		Name:            aws.String(f.name()),
		DurationSeconds: aws.Int32(int32(f.Duration.Seconds())),
		Policy:          aws.String(allowAllIAMPolicy),
	})
	if err != nil {
		return creds, err
	}

	log.Printf("Generated credentials %s using GetFederationToken, expires in %s", FormatKeyForDisplay(*resp.Credentials.AccessKeyId), time.Until(*resp.Credentials.Expiration).String())

	return aws.Credentials{
		AccessKeyID:     aws.ToString(resp.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(resp.Credentials.SecretAccessKey),
		SessionToken:    aws.ToString(resp.Credentials.SessionToken),
		CanExpire:       true,
		Expires:         aws.ToTime(resp.Credentials.Expiration),
	}, nil
}
