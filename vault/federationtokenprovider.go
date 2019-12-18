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

// Retrieve generates a new set of temporary credentials using STS GetFederationToken
func (f *FederationTokenProvider) Retrieve() (val credentials.Value, err error) {
	resp, err := f.StsClient.GetFederationToken(&sts.GetFederationTokenInput{
		Name:            aws.String(f.Name),
		DurationSeconds: aws.Int64(int64(f.Duration.Seconds())),
		Policy:          aws.String(allowAllIAMPolicy),
	})
	if err != nil {
		return val, err
	}

	log.Printf("Generated credentials %s using GetFederationToken, expires in %s", formatKeyForDisplay(*resp.Credentials.AccessKeyId), time.Until(*resp.Credentials.Expiration).String())

	f.SetExpiration(*resp.Credentials.Expiration, f.ExpiryWindow)
	return credentials.Value{
		AccessKeyID:     *resp.Credentials.AccessKeyId,
		SecretAccessKey: *resp.Credentials.SecretAccessKey,
		SessionToken:    *resp.Credentials.SessionToken,
	}, nil
}
