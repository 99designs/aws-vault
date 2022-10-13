package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/99designs/keyring"
	"github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/sso"
	ssotypes "github.com/aws/aws-sdk-go-v2/service/sso/types"
	"github.com/aws/aws-sdk-go-v2/service/ssooidc"
	ssooidctypes "github.com/aws/aws-sdk-go-v2/service/ssooidc/types"
	ststypes "github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/skratchdot/open-golang/open"
)

type OIDCTokenCacher interface {
	Get(string) (*ssooidc.CreateTokenOutput, error)
	Set(string, *ssooidc.CreateTokenOutput) error
	Remove(string) error
}

// SSORoleCredentialsProvider creates temporary credentials for an SSO Role.
type SSORoleCredentialsProvider struct {
	OIDCClient     *ssooidc.Client
	OIDCTokenCache OIDCTokenCacher
	StartURL       string
	SSOClient      *sso.Client
	AccountID      string
	RoleName       string
	UseStdout      bool
}

func millisecondsTimeValue(v int64) time.Time {
	return time.Unix(0, v*int64(time.Millisecond))
}

// Retrieve generates a new set of temporary credentials using SSO GetRoleCredentials.
func (p *SSORoleCredentialsProvider) Retrieve(ctx context.Context) (aws.Credentials, error) {
	creds, err := p.getRoleCredentials(ctx)
	if err != nil {
		return aws.Credentials{}, err
	}

	return aws.Credentials{
		AccessKeyID:     aws.ToString(creds.AccessKeyId),
		SecretAccessKey: aws.ToString(creds.SecretAccessKey),
		SessionToken:    aws.ToString(creds.SessionToken),
		CanExpire:       true,
		Expires:         millisecondsTimeValue(creds.Expiration),
	}, nil
}

func (p *SSORoleCredentialsProvider) getRoleCredentials(ctx context.Context) (*ssotypes.RoleCredentials, error) {
	token, cached, err := p.getOIDCToken(ctx)
	if err != nil {
		return nil, err
	}

	resp, err := p.SSOClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
		AccessToken: token.AccessToken,
		AccountId:   aws.String(p.AccountID),
		RoleName:    aws.String(p.RoleName),
	})
	if err != nil {
		if cached && p.OIDCTokenCache != nil {
			var rspError *awshttp.ResponseError
			if !errors.As(err, &rspError) {
				return nil, err
			}

			// If the error is a 401, remove the cached oidc token and try
			// again. This is a recursive call but it should only happen once
			// due to the cache being cleared before retrying.
			if rspError.HTTPStatusCode() == http.StatusUnauthorized {
				err = p.OIDCTokenCache.Remove(p.StartURL)
				if err != nil {
					return nil, err
				}
				return p.getRoleCredentials(ctx)
			}
		}
		return nil, err
	}
	log.Printf("Got credentials %s for SSO role %s (account: %s), expires in %s", FormatKeyForDisplay(*resp.RoleCredentials.AccessKeyId), p.RoleName, p.AccountID, time.Until(millisecondsTimeValue(resp.RoleCredentials.Expiration)).String())

	return resp.RoleCredentials, nil
}

// getRoleCredentialsAsStsCredemtials returns getRoleCredentials as sts.Credentials because sessions.Store expects it
func (p *SSORoleCredentialsProvider) getRoleCredentialsAsStsCredemtials(ctx context.Context) (*ststypes.Credentials, error) {
	creds, err := p.getRoleCredentials(ctx)
	if err != nil {
		return nil, err
	}

	return &ststypes.Credentials{
		AccessKeyId:     creds.AccessKeyId,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Expiration:      aws.Time(millisecondsTimeValue(creds.Expiration)),
	}, nil
}

func (p *SSORoleCredentialsProvider) getOIDCToken(ctx context.Context) (token *ssooidc.CreateTokenOutput, cached bool, err error) {
	if p.OIDCTokenCache != nil {
		token, err = p.OIDCTokenCache.Get(p.StartURL)
		if err != nil && err != keyring.ErrKeyNotFound {
			return nil, false, err
		}
		if token != nil {
			return token, true, nil
		}
	}
	token, err = p.newOIDCToken(ctx)
	if err != nil {
		return nil, false, err
	}

	if p.OIDCTokenCache != nil {
		err = p.OIDCTokenCache.Set(p.StartURL, token)
		if err != nil {
			return nil, false, err
		}
	}
	return token, false, err
}

func (p *SSORoleCredentialsProvider) newOIDCToken(ctx context.Context) (*ssooidc.CreateTokenOutput, error) {
	clientCreds, err := p.OIDCClient.RegisterClient(ctx, &ssooidc.RegisterClientInput{
		ClientName: aws.String("aws-vault"),
		ClientType: aws.String("public"),
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Created new OIDC client (expires at: %s)", time.Unix(clientCreds.ClientSecretExpiresAt, 0))

	deviceCreds, err := p.OIDCClient.StartDeviceAuthorization(ctx, &ssooidc.StartDeviceAuthorizationInput{
		ClientId:     clientCreds.ClientId,
		ClientSecret: clientCreds.ClientSecret,
		StartUrl:     aws.String(p.StartURL),
	})
	if err != nil {
		return nil, err
	}
	log.Printf("Created OIDC device code for %s (expires in: %ds)", p.StartURL, deviceCreds.ExpiresIn)

	if p.UseStdout {
		fmt.Fprintf(os.Stderr, "Open the SSO authorization page in a browser (use Ctrl-C to abort)\n%s\n", aws.ToString(deviceCreds.VerificationUriComplete))
	} else {
		log.Println("Opening SSO authorization page in browser")
		fmt.Fprintf(os.Stderr, "Opening the SSO authorization page in your default browser (use Ctrl-C to abort)\n%s\n", aws.ToString(deviceCreds.VerificationUriComplete))
		if err := open.Run(aws.ToString(deviceCreds.VerificationUriComplete)); err != nil {
			log.Printf("Failed to open browser: %s", err)
		}
	}

	// These are the default values defined in the following RFC:
	// https://tools.ietf.org/html/draft-ietf-oauth-device-flow-15#section-3.5
	var slowDownDelay = 5 * time.Second
	var retryInterval = 5 * time.Second

	if i := deviceCreds.Interval; i > 0 {
		retryInterval = time.Duration(i) * time.Second
	}

	for {
		t, err := p.OIDCClient.CreateToken(ctx, &ssooidc.CreateTokenInput{
			ClientId:     clientCreds.ClientId,
			ClientSecret: clientCreds.ClientSecret,
			DeviceCode:   deviceCreds.DeviceCode,
			GrantType:    aws.String("urn:ietf:params:oauth:grant-type:device_code"),
		})
		if err != nil {
			var sde *ssooidctypes.SlowDownException
			if errors.As(err, &sde) {
				retryInterval += slowDownDelay
			}

			var ape *ssooidctypes.AuthorizationPendingException
			if errors.As(err, &ape) {
				time.Sleep(retryInterval)
				continue
			}

			return nil, err
		}

		log.Printf("Created new OIDC access token for %s (expires in: %ds)", p.StartURL, t.ExpiresIn)
		return t, nil
	}
}
