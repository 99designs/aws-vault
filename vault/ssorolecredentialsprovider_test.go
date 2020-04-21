package vault_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/aws-vault/vault/vaultfakes"
	"github.com/99designs/keyring"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sso"
	"github.com/aws/aws-sdk-go/service/ssooidc"
)

func TestSSORoleCredentialsProvider(t *testing.T) {
	type expectations struct {
		registerClientCalls     int
		createTokenCalls        int
		startAuthorizationCalls int
		getRoleCredentialsCalls int
	}

	tests := []struct {
		name             string
		startURL         string
		tokenExpiration  time.Time
		clientExpiration time.Time
		expectations     *expectations
	}{
		{
			name:     "works",
			startURL: "https://login.awsapps.com/start",
			expectations: &expectations{
				registerClientCalls:     1,
				createTokenCalls:        1,
				startAuthorizationCalls: 1,
				getRoleCredentialsCalls: 1,
			},
		},
		{
			name:             "uses cache if it exists",
			startURL:         "https://cached.awsapps.com/start",
			tokenExpiration:  time.Now().Add(1 * time.Hour),
			clientExpiration: time.Now().Add(1 * time.Hour),
			expectations: &expectations{
				getRoleCredentialsCalls: 1,
			},
		},
		{
			name:            "registers new client on expiration",
			startURL:        "https://cached.awsapps.com/start",
			tokenExpiration: time.Now().Add(1 * time.Hour),
			expectations: &expectations{
				registerClientCalls:     1,
				getRoleCredentialsCalls: 1,
			},
		},
		{
			name:             "refreshes token on expiration",
			startURL:         "https://cached.awsapps.com/start",
			clientExpiration: time.Now().Add(1 * time.Hour),
			expectations: &expectations{
				createTokenCalls:        1,
				startAuthorizationCalls: 1,
				getRoleCredentialsCalls: 1,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			fakeSSOClient := &vaultfakes.FakeSSOClient{}
			fakeOIDCClient := &vaultfakes.FakeSSOOIDCClient{}

			fakeOIDCClient.RegisterClientReturns(&ssooidc.RegisterClientOutput{
				ClientId:              aws.String("id"),
				ClientSecret:          aws.String("secret"),
				ClientSecretExpiresAt: aws.Int64(time.Now().Unix()),
			}, nil)

			fakeOIDCClient.CreateTokenReturns(&ssooidc.CreateTokenOutput{
				AccessToken: aws.String("token"),
				ExpiresIn:   aws.Int64(3600),
			}, nil)

			fakeOIDCClient.StartDeviceAuthorizationReturns(&ssooidc.StartDeviceAuthorizationOutput{
				DeviceCode:              aws.String("1234"),
				VerificationUriComplete: aws.String("https://device.sso.eu-west-1.amazonaws.com/?user_code=HZZB-FPRL"),
			}, nil)

			fakeSSOClient.GetRoleCredentialsReturns(&sso.GetRoleCredentialsOutput{
				RoleCredentials: &sso.RoleCredentials{
					AccessKeyId:     aws.String("accesskeyid"),
					SecretAccessKey: aws.String("secret"),
					SessionToken:    aws.String("token"),
					Expiration:      aws.Int64(time.Now().Add(1*time.Hour).Unix() * 1000),
				},
			}, nil)

			fakeKeyring := keyring.NewArrayKeyring([]keyring.Item{
				{
					Key:  "https://cached.awsapps.com/start",
					Data: []byte(newTestCredentialsData(t, tt.tokenExpiration, tt.clientExpiration)),
				},
			})

			ssoOIDCProvider := &vault.SSOOIDCProvider{
				Keyring:              &vault.CredentialKeyring{Keyring: fakeKeyring},
				OIDCClient:           fakeOIDCClient,
				StartURL:             tt.startURL,
				DisableSystemBrowser: true,
			}

			p := &vault.SSORoleCredentialsProvider{
				OIDCProvider: ssoOIDCProvider,
				SSOClient:    fakeSSOClient,
				AccountID:    "1234567890012",
				RoleName:     "Administrator",
				ExpiryWindow: 1 * time.Minute,
			}

			creds, err := p.Retrieve()
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if creds.AccessKeyID != "accesskeyid" {
				t.Fatalf("unexpected credentials: %v", creds)
			}

			assertEqualCount(t, fakeOIDCClient.RegisterClientCallCount(), tt.expectations.registerClientCalls, "register client")
			assertEqualCount(t, fakeOIDCClient.CreateTokenCallCount(), tt.expectations.createTokenCalls, "create token")
			assertEqualCount(t, fakeOIDCClient.StartDeviceAuthorizationCallCount(), tt.expectations.startAuthorizationCalls, "start authorization")
			assertEqualCount(t, fakeSSOClient.GetRoleCredentialsCallCount(), tt.expectations.getRoleCredentialsCalls, "get role credentials")

		})
	}
}

func assertEqualCount(t *testing.T, want int, got int, message string) {
	if got != want {
		t.Errorf("%s: call count %d != %d", message, got, want)
	}
}

func newTestCredentialsData(t *testing.T, tokenExpiration, clientExpiration time.Time) []byte {
	tpl := `{"Token":{"Token":"token","Expiration":"%s"},"Client":{"ID":"id","Secret":"secret","Expiration":"%s"}}`
	out := fmt.Sprintf(tpl, tokenExpiration.Format(time.RFC3339), clientExpiration.Format(time.RFC3339))
	return []byte(out)
}
