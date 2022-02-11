package vault

import (
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"reflect"
	"testing"
)

type MockEnvironment struct {
	environment map[string]string
}

func (m *MockEnvironment) Get(name string) string {
	if value, ok := m.environment[name]; ok {
		return value
	}
	return ""
}

func TestEnvironmentVariablesCredentialsProvider_Retrieve(t *testing.T) {
	tests := []struct {
		name        string
		environment map[string]string
		wantCreds   aws.Credentials
		wantErr     bool
	}{
		{
			name:        "no credentials in environment",
			environment: map[string]string{},
			wantErr:     true,
		},
		{
			name:        "no session token in environment",
			environment: map[string]string{"AWS_ACCESS_KEY_ID": "foo", "AWS_SECRET_ACCESS_KEY": "bar"},
			wantErr:     false, // handled at the 'login' command level, not provider level
			wantCreds:   aws.Credentials{AccessKeyID: "foo", SecretAccessKey: "bar", SessionToken: "", CanExpire: false},
		},
		{
			name:        "all credentials in environment",
			environment: map[string]string{"AWS_ACCESS_KEY_ID": "foo", "AWS_SECRET_ACCESS_KEY": "bar", "AWS_SESSION_TOKEN": "foobar"},
			wantErr:     false,
			wantCreds:   aws.Credentials{AccessKeyID: "foo", SecretAccessKey: "bar", SessionToken: "foobar", CanExpire: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &EnvironmentVariablesCredentialsProvider{
				env: &MockEnvironment{tt.environment},
			}
			gotCreds, err := m.Retrieve(context.TODO())
			if (err != nil) != tt.wantErr {
				t.Errorf("Retrieve() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotCreds, tt.wantCreds) {
				t.Errorf("Retrieve() gotCreds = %v, want %v", gotCreds, tt.wantCreds)
			}
		})
	}
}
