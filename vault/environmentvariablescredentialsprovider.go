package vault

import (
	"context"
	"fmt"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

// EnvironmentVariablesCredentialsProvider retrieves AWS credentials available in the OS environment variables
type EnvironmentVariablesCredentialsProvider struct {
}

func (m *EnvironmentVariablesCredentialsProvider) Retrieve(context.Context) (aws.Credentials, error) {
	configFromEnv, err := config.NewEnvConfig()
	if err != nil {
		err := fmt.Errorf("unable to authenticate to AWS through your environment variables: %w", err)
		return aws.Credentials{}, err
	}
	return configFromEnv.Credentials, nil
}
