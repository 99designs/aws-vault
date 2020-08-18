package vault

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/service/sso"
	"github.com/aws/aws-sdk-go/service/ssooidc"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/skratchdot/open-golang/open"
)

type OIDCTokenCacher interface {
	Get(string) (*ssooidc.CreateTokenOutput, error)
	Set(string, *ssooidc.CreateTokenOutput) error
}

// SSORoleCredentialsProvider creates temporary credentials for an SSO Role.
type SSORoleCredentialsProvider struct {
	OIDCClient     *ssooidc.SSOOIDC
	OIDCTokenCache OIDCTokenCacher
	StartURL       string
	SSOClient      *sso.SSO
	AccountID      string
	RoleName       string
	ExpiryWindow   time.Duration
	credentials.Expiry
}

// Retrieve generates a new set of temporary credentials using SSO GetRoleCredentials.
func (p *SSORoleCredentialsProvider) Retrieve() (credentials.Value, error) {
	creds, err := p.getRoleCredentials()
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(aws.MillisecondsTimeValue(creds.Expiration), p.ExpiryWindow)
	return credentials.Value{
		AccessKeyID:     aws.StringValue(creds.AccessKeyId),
		SecretAccessKey: aws.StringValue(creds.SecretAccessKey),
		SessionToken:    aws.StringValue(creds.SessionToken),
	}, nil
}

func (p *SSORoleCredentialsProvider) getRoleCredentials() (*sso.RoleCredentials, error) {
	token, err := p.getOIDCToken()
	if err != nil {
		return nil, err
	}

	resp, err := p.SSOClient.GetRoleCredentials(&sso.GetRoleCredentialsInput{
		AccessToken: token.AccessToken,
		AccountId:   aws.String(p.AccountID),
		RoleName:    aws.String(p.RoleName),
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Got credentials %s for SSO role %s (account: %s), expires in %s", FormatKeyForDisplay(*resp.RoleCredentials.AccessKeyId), p.RoleName, p.AccountID, time.Until(aws.MillisecondsTimeValue(resp.RoleCredentials.Expiration)).String())

	return resp.RoleCredentials, nil
}

// getRoleCredentialsAsStsCredemtials returns getRoleCredentials as sts.Credentials because sessions.Store expects it
func (p *SSORoleCredentialsProvider) getRoleCredentialsAsStsCredemtials() (*sts.Credentials, error) {
	creds, err := p.getRoleCredentials()
	if err != nil {
		return nil, err
	}

	return &sts.Credentials{
		AccessKeyId:     creds.AccessKeyId,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      aws.Time(aws.MillisecondsTimeValue(creds.Expiration)),
	}, nil
}

func (p *SSORoleCredentialsProvider) getOIDCToken() (token *ssooidc.CreateTokenOutput, err error) {
	if p.OIDCTokenCache != nil {
		token, err = p.OIDCTokenCache.Get(p.StartURL)
		if err != nil && err != keyring.ErrKeyNotFound {
			return nil, err
		}
	}
	if token == nil {
		token, err = p.newOIDCToken()
		if err != nil {
			return nil, err
		}

		if p.OIDCTokenCache != nil {
			err = p.OIDCTokenCache.Set(p.StartURL, token)
			if err != nil {
				return nil, err
			}
		}
	}
	return token, err
}

func (p *SSORoleCredentialsProvider) newOIDCToken() (*ssooidc.CreateTokenOutput, error) {
	clientCreds, err := p.OIDCClient.RegisterClient(&ssooidc.RegisterClientInput{
		ClientName: aws.String("aws-vault"),
		ClientType: aws.String("public"),
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Created new OIDC client (expires at: %s)", time.Unix(aws.Int64Value(clientCreds.ClientSecretExpiresAt), 0))

	deviceCreds, err := p.OIDCClient.StartDeviceAuthorization(&ssooidc.StartDeviceAuthorizationInput{
		ClientId:     clientCreds.ClientId,
		ClientSecret: clientCreds.ClientSecret,
		StartUrl:     aws.String(p.StartURL),
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Created OIDC device code for %s (expires in: %ds)", p.StartURL, aws.Int64Value(deviceCreds.ExpiresIn))

	log.Println("Opening SSO authorization page in browser")
	fmt.Fprintf(os.Stderr, "Opening the SSO authorization page in your default browser (use Ctrl-C to abort)\n%s\n", aws.StringValue(deviceCreds.VerificationUriComplete))
	if err := open.Run(aws.StringValue(deviceCreds.VerificationUriComplete)); err != nil {
		log.Printf("Failed to open browser: %s", err)
	}

	// These are the default values defined in the following RFC:
	// https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.5
	var slowDownDelay = 5 * time.Second
	var retryInterval = 5 * time.Second

	if i := aws.Int64Value(deviceCreds.Interval); i > 0 {
		retryInterval = time.Duration(i) * time.Second
	}

	for {
		t, err := p.OIDCClient.CreateToken(&ssooidc.CreateTokenInput{
			ClientId:     clientCreds.ClientId,
			ClientSecret: clientCreds.ClientSecret,
			DeviceCode:   deviceCreds.DeviceCode,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
		})
		if err != nil {
			e, ok := err.(awserr.Error)
			if !ok {
				return nil, err
			}
			switch e.Code() {
			case ssooidc.ErrCodeSlowDownException:
				retryInterval += slowDownDelay
				fallthrough
			case ssooidc.ErrCodeAuthorizationPendingException:
				time.Sleep(retryInterval)
				continue
			default:
				return nil, err
			}
		}

		log.Printf("Created new OIDC access token for %s (expires in: %ds)", p.StartURL, aws.Int64Value(t.ExpiresIn))
		return t, nil
	}
}
