package vault

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
)

func executeFail(process string) (string, error) {
	return "", errors.New("executing process failed")
}

func executeGetBadJSON(process string) (string, error) {
	return "Junk", nil
}

func executeGetCredential(accessKeyID *string, expiration *time.Time, secretAccesKey *string, sessionToken *string) (string, error) {
	v, err := json.Marshal(ststypes.Credentials{
		AccessKeyId:     accessKeyID,
		Expiration:      expiration,
		SecretAccessKey: secretAccesKey,
		SessionToken:    sessionToken,
	})
	return string(v), err
}

func TestCredentialProcessProvider_Retrieve(t *testing.T) {
	accessKeyID := "abcd"
	expiration := time.Time{}
	secretAccessKey := "0123"
	sessionToken := "4567"

	want := aws.Credentials{
		AccessKeyID:     accessKeyID,
		Expires:         expiration,
		CanExpire:       true,
		SecretAccessKey: secretAccessKey,
		SessionToken:    sessionToken,
	}

	tests := []struct {
		name                string
		execFunc            func(string) (string, error)
		wantErr             bool
		expectMissingFields bool
	}{
		{
			name:                "process execution fails",
			execFunc:            executeFail,
			wantErr:             true,
			expectMissingFields: false,
		},
		{
			name:                "bad json",
			execFunc:            executeGetBadJSON,
			wantErr:             true,
			expectMissingFields: false,
		},
		{
			name: "successful execution, good cred",
			execFunc: func(string) (string, error) {
				return executeGetCredential(&accessKeyID, &expiration, &secretAccessKey, &sessionToken)
			},
			wantErr:             false,
			expectMissingFields: false,
		},
		{
			name: "fields missing",
			execFunc: func(string) (string, error) {
				return executeGetCredential(nil, nil, nil, nil)
			},
			wantErr:             true,
			expectMissingFields: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			provider := CredentialProcessProvider{
				CredentialProcess: "",
			}
			got, err := provider.retrieveWith(ctx, tt.execFunc)

			if (err != nil) != tt.wantErr {
				t.Errorf("CredentialProcessProvider.Retrieve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && !reflect.DeepEqual(got, want) {
				t.Errorf("CredentialProcessProvider.Retrieve() = %v, want %v", got, want)
			}

			if tt.wantErr && tt.expectMissingFields {
				for _, expectedMissingField := range credentialProcessRequiredFields {
					if !strings.Contains(err.Error(), expectedMissingField) {
						t.Errorf("expected field '%v' not present in error: %v'", expectedMissingField, err)
					}
				}
			}
		})
	}
}
