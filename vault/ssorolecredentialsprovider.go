package vault

import (
	"encoding/json"
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

const (
	ssoClientName         = "aws-vault"
	ssoClientType         = "public"
	oAuthTokenGrantType   = "urn:ietf:params:oauth:grant-type:device_code"
	authorizationTemplate = "Opening the SSO authorization page in your default browser (use Ctrl-C to abort)\n%s\n"
)

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . SSOOIDCClient
type SSOOIDCClient interface {
	CreateToken(*ssooidc.CreateTokenInput) (*ssooidc.CreateTokenOutput, error)
	RegisterClient(*ssooidc.RegisterClientInput) (*ssooidc.RegisterClientOutput, error)
	StartDeviceAuthorization(*ssooidc.StartDeviceAuthorizationInput) (*ssooidc.StartDeviceAuthorizationOutput, error)
}

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 . SSOClient
type SSOClient interface {
	GetRoleCredentials(*sso.GetRoleCredentialsInput) (*sso.GetRoleCredentialsOutput, error)
}

// CachedSSORoleCredentialsProvider uses the keyring to cache SSO Role sessions.
type CachedSSORoleCredentialsProvider struct {
	CredentialsName string
	Keyring         *SessionKeyring
	Provider        *SSORoleCredentialsProvider
	ExpiryWindow    time.Duration
	credentials.Expiry
}

// Retrieve the cached credentials or generate new ones.
func (p *CachedSSORoleCredentialsProvider) Retrieve() (credentials.Value, error) {
	key := SessionKey{
		Type:        "sso",
		ProfileName: p.CredentialsName,
	}
	creds, err := p.Keyring.Get(key)
	if err != nil {
		// lookup missed, we need to create a new one.
		creds, err = p.Provider.GetRoleCredentials()
		if err != nil {
			return credentials.Value{}, err
		}

		err = p.Keyring.Set(key, creds)
		if err != nil {
			return credentials.Value{}, err
		}
	} else {
		log.Printf("Re-using cached credentials %s generated from GetRoleCredentials, expires in %s", FormatKeyForDisplay(*creds.AccessKeyId), time.Until(*creds.Expiration).String())
	}

	p.SetExpiration(*creds.Expiration, p.ExpiryWindow)

	return credentials.Value{
		AccessKeyID:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
	}, nil
}

// SSORoleCredentialsProvider creates temporary credentials for an SSO Role.
type SSORoleCredentialsProvider struct {
	OIDCProvider *SSOOIDCProvider
	SSOClient    SSOClient
	AccountID    string
	RoleName     string
	ExpiryWindow time.Duration
	credentials.Expiry
}

// Retrieve generates a new set of temporary credentials using SSO GetRoleCredentials.
func (p *SSORoleCredentialsProvider) Retrieve() (credentials.Value, error) {
	creds, err := p.GetRoleCredentials()
	if err != nil {
		return credentials.Value{}, err
	}

	p.SetExpiration(*creds.Expiration, p.ExpiryWindow)
	return credentials.Value{
		AccessKeyID:     *creds.AccessKeyId,
		SecretAccessKey: *creds.SecretAccessKey,
		SessionToken:    *creds.SessionToken,
	}, nil
}

func (p *SSORoleCredentialsProvider) GetRoleCredentials() (*sts.Credentials, error) {
	token, err := p.OIDCProvider.GetAccessToken()
	if err != nil {
		return nil, err
	}

	resp, err := p.SSOClient.GetRoleCredentials(&sso.GetRoleCredentialsInput{
		AccessToken: aws.String(token.Token),
		AccountId:   aws.String(p.AccountID),
		RoleName:    aws.String(p.RoleName),
	})
	if err != nil {
		return nil, err
	}

	expiration := aws.MillisecondsTimeValue(resp.RoleCredentials.Expiration)

	// This is needed because sessions.Store expects a sts.Credentials object.
	creds := &sts.Credentials{
		AccessKeyId:     resp.RoleCredentials.AccessKeyId,
		SecretAccessKey: resp.RoleCredentials.SecretAccessKey,
		SessionToken:    resp.RoleCredentials.SessionToken,
		Expiration:      aws.Time(expiration),
	}

	log.Printf("Got credentials %s for SSO role %s (account: %s), expires in %s", FormatKeyForDisplay(*resp.RoleCredentials.AccessKeyId), p.RoleName, p.AccountID, time.Until(expiration).String())

	return creds, nil
}

type SSOClientCredentials struct {
	ID         string
	Secret     string
	Expiration time.Time
}

type SSOAccessToken struct {
	Token      string
	Expiration time.Time
}

type SSOOIDCProvider struct {
	OIDCClient           SSOOIDCClient
	Keyring              *CredentialKeyring
	StartURL             string
	DisableSystemBrowser bool
}

func (p *SSOOIDCProvider) GetAccessToken() (*SSOAccessToken, error) {
	var (
		creds = &struct {
			Token  *SSOAccessToken
			Client *SSOClientCredentials
		}{
			Client: &SSOClientCredentials{},
			Token:  &SSOAccessToken{},
		}
		credsUpdated bool
	)

	item, err := p.Keyring.Keyring.Get(p.StartURL)
	if err != nil && err != keyring.ErrKeyNotFound {
		return nil, err
	}

	if item.Data != nil {
		if err = json.Unmarshal(item.Data, &creds); err != nil {
			return nil, fmt.Errorf("Invalid data in keyring: %v", err)
		}
	}

	if creds.Client.Expiration.Before(time.Now()) {
		creds.Client, err = p.registerNewClient()
		if err != nil {
			return nil, err
		}
		log.Printf("Created new SSO client for %s (expires at: %s)", p.StartURL, creds.Client.Expiration.String())
		credsUpdated = true
	}

	if creds.Token.Expiration.Before(time.Now()) {
		creds.Token, err = p.createClientToken(creds.Client)
		if err != nil {
			return nil, err
		}
		log.Printf("Created new SSO access token for %s (expires at: %s)", p.StartURL, creds.Token.Expiration.String())
		credsUpdated = true
	}

	if credsUpdated {
		bytes, err := json.Marshal(creds)
		if err != nil {
			return nil, err
		}
		err = p.Keyring.Keyring.Set(keyring.Item{
			Key:                         p.StartURL,
			Label:                       fmt.Sprintf("aws-vault (%s)", p.StartURL),
			Data:                        bytes,
			KeychainNotTrustApplication: true,
		})
		if err != nil {
			return nil, err
		}
	}

	return creds.Token, nil
}

func (p *SSOOIDCProvider) registerNewClient() (*SSOClientCredentials, error) {
	c, err := p.OIDCClient.RegisterClient(&ssooidc.RegisterClientInput{
		ClientName: aws.String(ssoClientName),
		ClientType: aws.String(ssoClientType),
	})
	if err != nil {
		return nil, err
	}
	return &SSOClientCredentials{
		ID:         aws.StringValue(c.ClientId),
		Secret:     aws.StringValue(c.ClientSecret),
		Expiration: time.Unix(aws.Int64Value(c.ClientSecretExpiresAt), 0),
	}, nil
}

func (p *SSOOIDCProvider) createClientToken(creds *SSOClientCredentials) (*SSOAccessToken, error) {
	auth, err := p.OIDCClient.StartDeviceAuthorization(&ssooidc.StartDeviceAuthorizationInput{
		ClientId:     aws.String(creds.ID),
		ClientSecret: aws.String(creds.Secret),
		StartUrl:     aws.String(p.StartURL),
	})
	if err != nil {
		return nil, err
	}
	fmt.Fprintf(os.Stderr, authorizationTemplate, aws.StringValue(auth.VerificationUriComplete))

	if !p.DisableSystemBrowser {
		if err := open.Run(aws.StringValue(auth.VerificationUriComplete)); err != nil {
			log.Printf("failed to open browser: %s", err)
		}
	}

	var (
		// These are the default values defined in the following RFC:
		// https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.5
		slowDownDelay = 5 * time.Second
		retryInterval = 5 * time.Second
	)
	if i := aws.Int64Value(auth.Interval); i > 0 {
		retryInterval = time.Duration(i) * time.Second
	}

	for {
		t, err := p.OIDCClient.CreateToken(&ssooidc.CreateTokenInput{
			ClientId:     aws.String(creds.ID),
			ClientSecret: aws.String(creds.Secret),
			DeviceCode:   auth.DeviceCode,
			GrantType:    aws.String(oAuthTokenGrantType),
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
		expiresInSecs := time.Duration(aws.Int64Value(t.ExpiresIn)) * time.Second

		return &SSOAccessToken{
			Token:      aws.StringValue(t.AccessToken),
			Expiration: time.Now().Add(expiresInSecs),
		}, nil
	}
}
