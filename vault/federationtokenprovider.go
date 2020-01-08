package vault

import (
	"log"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sts"
)

const allowAllIAMPolicy = `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`

// FederationTokenProvider retrieves temporary credentials from STS using GetFederationToken
type FederationTokenProvider struct {
	StsClient    *sts.STS
	Name         string
	Duration     time.Duration
	ExpiryWindow time.Duration
	credentials.Expiry
}

func (f *FederationTokenProvider) name() string {
	// truncate the username if it's longer than 32 characters or else GetFederationToken will fail. see: https://docs.aws.amazon.com/STS/latest/APIReference/API_GetFederationToken.html
	if len(f.Name) > 32 {
		return f.Name[0:32]
	}
	return f.Name
}

// Retrieve generates a new set of temporary credentials using STS GetFederationToken
func (f *FederationTokenProvider) Retrieve() (val credentials.Value, err error) {
	resp, err := f.StsClient.GetFederationToken(&sts.GetFederationTokenInput{
		Name:            aws.String(f.name()),
		DurationSeconds: aws.Int64(int64(f.Duration.Seconds())),
		Policy:          aws.String(allowAllIAMPolicy),
	})
	if err != nil {
		return val, err
	}

	log.Printf("Generated credentials %s using GetFederationToken, expires in %s", FormatKeyForDisplay(*resp.Credentials.AccessKeyId), time.Until(*resp.Credentials.Expiration).String())

	f.SetExpiration(*resp.Credentials.Expiration, f.ExpiryWindow)
	return credentials.Value{
		AccessKeyID:     *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		SessionToken:    *resp.Credentials.SessionToken,
	}, nil
}
