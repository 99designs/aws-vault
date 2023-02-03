package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

var credentialProcessRequiredFields = []string{"AccessKeyId", "Expiration", "SecretAccessKey", "SessionToken"}

// CredentialProcessProvider implements interface aws.CredentialsProvider to retrieve credentials from an external executable
// as described in https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
type CredentialProcessProvider struct {
	CredentialProcess string
}

func (p *CredentialProcessProvider) validateJSONCredential(cred *ststypes.Credentials) error {
	var missing []string

	h := reflect.ValueOf(cred).Elem()
	for _, requiredField := range credentialProcessRequiredFields {
		if h.FieldByName(requiredField).IsNil() {
			missing = append(missing, requiredField)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("JSON credential from command %q missing the following fields: %v", p.CredentialProcess, missing)
	}

	return nil
}

// Retrieve obtains a new set of temporary credentials using an external process, required to satisfy interface aws.CredentialsProvider
func (p *CredentialProcessProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	return p.retrieveWith(ctx, executeProcess)
}

func (p *CredentialProcessProvider) retrieveWith(ctx context.Context, fn func(string) (string, error)) (aws.Credentials, error) {
	creds, err := p.callCredentialProcessWith(ctx, fn)
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

func (p *CredentialProcessProvider) callCredentialProcess(ctx context.Context) (*ststypes.Credentials, error) {
	return p.callCredentialProcessWith(ctx, executeProcess)
}

func (p *CredentialProcessProvider) callCredentialProcessWith(_ context.Context, fn func(string) (string, error)) (*ststypes.Credentials, error) {
	// Exec CredentialProcess to retrieve AWS creds in JSON format as described in
	// https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
	output, err := fn(p.CredentialProcess)

	if err != nil {
		return nil, err
	}

	// Unmarshal the JSON into a ststypes.Credentials object
	var value ststypes.Credentials
	if err := json.Unmarshal([]byte(output), &value); err != nil {
		return &ststypes.Credentials{}, fmt.Errorf("invalid JSON format from command %q: %v", p.CredentialProcess, err)
	}

	// Validate that all required fields were present in JSON before returning
	return &value, p.validateJSONCredential(&value)
}
