package vault

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"log"
	"os"
)

// EnvironmentVariablesCredentialsProvider retrieves AWS credentials available in the OS environment variables
type EnvironmentVariablesCredentialsProvider struct {
	env EnvironmentVariablesProvider
}

const accessKeyIdEnvKey = "AWS_ACCESS_KEY_ID"
const secretAccessKeyEnvKey = "AWS_SECRET_ACCESS_KEY"
const sessionTokenEnvKey = "AWS_SESSION_TOKEN"

func (m *EnvironmentVariablesCredentialsProvider) Retrieve(context.Context) (creds aws.Credentials, err error) {
	accessKeyId := m.env.Get(accessKeyIdEnvKey)
	secretAccessKey := m.env.Get(secretAccessKeyEnvKey)
	sessionToken := m.env.Get(sessionTokenEnvKey)

	if accessKeyId == "" || secretAccessKey == "" {
		err := fmt.Errorf(
			"missing AWS credentials in your environment.\n You need to set at least %s and %s.",
			accessKeyIdEnvKey, secretAccessKeyEnvKey,
		)
		return aws.Credentials{}, err
	}

	if sessionToken == "" {
		log.Printf("%s not found in environment variables. If using aws-vault login, "+
			"you need to specify it in your environment since generating a sign-in link requires temporary credentials",
			sessionTokenEnvKey,
		)
	}

	return aws.Credentials{
		AccessKeyID:     accessKeyId,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
		CanExpire:       sessionToken != "",
	}, nil
}

// EnvironmentVariablesProvider is an interface to retrieve the value of environment variables
// Useful for testing
type EnvironmentVariablesProvider interface {
	Get(name string) string
}

type environmentVariablesProviderImpl struct{}

func (m *environmentVariablesProviderImpl) Get(name string) string {
	return os.Getenv(name)
}
