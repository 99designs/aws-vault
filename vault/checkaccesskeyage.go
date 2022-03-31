package vault

import (
	"context"
	"fmt"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iam"
)

// GetUsernameFromSession returns the IAM username (or root) associated with the current aws session
func getAccessKeyAge(cfg aws.Config) (time.Duration, error) {
	iamClient := iam.NewFromConfig(cfg)

	keys, err := iamClient.ListAccessKeys(
		context.TODO(),
		&iam.ListAccessKeysInput{},
	)
	if err != nil {
		return 0, err
	} else if len(keys.AccessKeyMetadata) == 0 {
		return 0, fmt.Errorf("failed to retrieve access key")
	}

	keyCreationDate := keys.AccessKeyMetadata[0].CreateDate
	keyAge := time.Now().UTC().Sub(*keyCreationDate)

	return keyAge, nil
}

func CheckAccessKeyAge(config *Config, keyring keyring.Keyring) {
	ckr := &CredentialKeyring{Keyring: keyring}
	masterCredentialsName, err := FindMasterCredentialsNameFor(config.ProfileName, ckr, config)
	if err != nil {
		fmt.Println("Could not find master credentials")
		return
	}

	credsProvider := NewMasterCredentialsProvider(ckr, masterCredentialsName)
	cfg := NewAwsConfigWithCredsProvider(credsProvider, config.Region, config.STSRegionalEndpoints)
	keyAge, err := getAccessKeyAge(cfg)

	if err != nil {
		fmt.Println("Failed to retrieve access key age")
	} else if keyAge > config.AccessKeyLifetimeWarningAge {
		fmt.Printf("Please rotate your access key by executing 'aws-vault rotate %s'\n", config.ProfileName)
	}
}
