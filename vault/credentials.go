package vault

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
)

const (
	ServiceName        = "aws-vault"
	SessionServiceName = "aws-vault.sessions"
)

type Credentials struct {
	AccessKeyId string
	SecretKey   string
}

func (c Credentials) Environ() []string {
	return []string{
		"AWS_ACCESS_KEY_ID=" + c.AccessKeyId,
		"AWS_SECRET_ACCESS_KEY=" + c.SecretKey,
	}
}

func (c Credentials) AwsConfig() *aws.Config {
	return aws.DefaultConfig.WithCredentials(credentials.NewStaticCredentials(
		c.AccessKeyId, c.SecretKey, "",
	))
}
