package vault

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	ssoTokenLock   SSOTokenLock
	ssoLockWait    time.Duration
	ssoLockLog     time.Duration
	ssoNow         func() time.Time
	ssoSleep       func(context.Context, time.Duration) error
	ssoLogf        func(string, ...any)
	newOIDCTokenFn func(context.Context) (*ssooidc.CreateTokenOutput, error)
}

func millisecondsTimeValue(v int64) time.Time {
	return time.Unix(0, v*int64(time.Millisecond))
}

const (
	defaultSSOLockWaitDelay = 100 * time.Millisecond
	defaultSSOLockLogEvery  = 15 * time.Second
	defaultSSOLockWarnAfter = 5 * time.Second
	// 0 means retry indefinitely (caller is expected to use context cancellation).
	ssoMaxAttempts          = 0
	ssoRetryBase            = 200 * time.Millisecond
	ssoRetryMax             = 5 * time.Second
	ssoRetryAfterJitterMin  = 1.1
	ssoRetryAfterJitterMax  = 1.3
)

func defaultSSOSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (p *SSORoleCredentialsProvider) ensureSSODependencies() {
	if p.ssoTokenLock == nil && !p.UseStdout {
		p.ssoTokenLock = NewDefaultSSOTokenLock()
	}
	if p.ssoLockWait == 0 {
		p.ssoLockWait = defaultSSOLockWaitDelay
	}
	if p.ssoLockLog == 0 {
		p.ssoLockLog = defaultSSOLockLogEvery
	}
	if p.ssoNow == nil {
		p.ssoNow = time.Now
	}
	if p.ssoSleep == nil {
		p.ssoSleep = defaultSSOSleep
	}
	if p.ssoLogf == nil {
		p.ssoLogf = log.Printf
	}
	if p.newOIDCTokenFn == nil {
		p.newOIDCTokenFn = p.newOIDCToken
	}
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
	p.ensureSSODependencies()

	token, cached, err := p.getOIDCToken(ctx)
	if err != nil {
		return nil, err
	}

	maxAttempts, baseDelay, maxDelay := ssoRetrySettings()
	attempt := 0
	for {
		attempt++
		resp, err := p.SSOClient.GetRoleCredentials(ctx, &sso.GetRoleCredentialsInput{
			AccessToken: token.AccessToken,
			AccountId:   aws.String(p.AccountID),
			RoleName:    aws.String(p.RoleName),
		})
		if err == nil {
			log.Printf("Got credentials %s for SSO role %s (account: %s), expires in %s", FormatKeyForDisplay(*resp.RoleCredentials.AccessKeyId), p.RoleName, p.AccountID, time.Until(millisecondsTimeValue(resp.RoleCredentials.Expiration)).String())
			return resp.RoleCredentials, nil
		}

		if cached && p.OIDCTokenCache != nil {
			var rspError *awshttp.ResponseError
			if errors.As(err, &rspError) && rspError.HTTPStatusCode() == http.StatusUnauthorized {
				// Cached token rejected: drop it and retry with a fresh access token.
				// This should only happen once because the cache is cleared before retrying.
				if err = p.OIDCTokenCache.Remove(p.StartURL); err != nil {
					return nil, err
				}
				token, cached, err = p.getOIDCToken(ctx)
				if err != nil {
					return nil, err
				}
				attempt = 0
				continue
			}
		}

		if isSSORateLimitError(err) {
			if maxAttempts == 0 || attempt < maxAttempts {
				attemptInfo := fmt.Sprintf("%d/%d", attempt, maxAttempts)
				if maxAttempts == 0 {
					attemptInfo = fmt.Sprintf("%d/inf", attempt)
				}
				if retryAfter, ok := retryAfterFromError(err); ok {
					delay := jitterRetryAfter(retryAfter)
					log.Printf("SSO rate limited for role %s (account: %s); retry-after %s (jittered %s), attempt %s", p.RoleName, p.AccountID, retryAfter, delay, attemptInfo)
					if err = p.ssoSleep(ctx, delay); err != nil {
						return nil, err
					}
					continue
				}
				delay := jitteredBackoff(baseDelay, maxDelay, attempt)
				log.Printf("SSO rate limited for role %s (account: %s); backing off %s (synthetic), attempt %s", p.RoleName, p.AccountID, delay, attemptInfo)
				if err = p.ssoSleep(ctx, delay); err != nil {
					return nil, err
				}
				continue
			}
		}

		return nil, err
	}
}

func (p *SSORoleCredentialsProvider) RetrieveStsCredentials(ctx context.Context) (*ststypes.Credentials, error) {
	return p.getRoleCredentialsAsStsCredemtials(ctx)
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
	p.ensureSSODependencies()

	token, cached, err = p.getCachedOIDCToken()
	if err != nil || token != nil {
		return token, cached, err
	}

	if p.UseStdout {
		return p.createAndCacheOIDCToken(ctx)
	}

	return p.getOIDCTokenWithLock(ctx)
}

func (p *SSORoleCredentialsProvider) getCachedOIDCToken() (token *ssooidc.CreateTokenOutput, cached bool, err error) {
	if p.OIDCTokenCache == nil {
		return nil, false, nil
	}

	token, err = p.OIDCTokenCache.Get(p.StartURL)
	if err != nil && err != keyring.ErrKeyNotFound {
		return nil, false, err
	}
	if token != nil {
		return token, true, nil
	}

	return nil, false, nil
}

func (p *SSORoleCredentialsProvider) createAndCacheOIDCToken(ctx context.Context) (token *ssooidc.CreateTokenOutput, cached bool, err error) {
	token, err = p.newOIDCTokenFn(ctx)
	if err != nil {
		return nil, false, err
	}

	if p.OIDCTokenCache != nil {
		if err = p.OIDCTokenCache.Set(p.StartURL, token); err != nil {
			return nil, false, err
		}
	}

	return token, false, nil
}

func (p *SSORoleCredentialsProvider) getOIDCTokenWithLock(ctx context.Context) (token *ssooidc.CreateTokenOutput, cached bool, err error) {
	var lastLog time.Time
	var waitStart time.Time
	warned := false

	for {
		token, cached, err = p.getCachedOIDCToken()
		if err != nil || token != nil {
			return token, cached, err
		}
		if ctx.Err() != nil {
			return nil, false, ctx.Err()
		}

		locked, err := p.ssoTokenLock.TryLock()
		if err != nil {
			return nil, false, err
		}
		if locked {
			token, cached, err = p.getCachedOIDCToken()
			if err != nil || token != nil {
				unlockErr := p.ssoTokenLock.Unlock()
				if unlockErr != nil {
					return nil, false, unlockErr
				}
				return token, cached, err
			}

			token, err = p.newOIDCTokenFn(ctx)
			if err != nil {
				unlockErr := p.ssoTokenLock.Unlock()
				if unlockErr != nil {
					return nil, false, unlockErr
				}
				return nil, false, err
			}

			if p.OIDCTokenCache != nil {
				if err = p.OIDCTokenCache.Set(p.StartURL, token); err != nil {
					unlockErr := p.ssoTokenLock.Unlock()
					if unlockErr != nil {
						return nil, false, unlockErr
					}
					return nil, false, err
				}
			}

			if err = p.ssoTokenLock.Unlock(); err != nil {
				return nil, false, err
			}

			return token, false, nil
		}

		now := p.ssoNow()
		if waitStart.IsZero() {
			waitStart = now
		}
		if !warned && now.Sub(waitStart) >= defaultSSOLockWarnAfter {
			fmt.Fprintf(os.Stderr, "Waiting for SSO lock at %s\n", p.ssoTokenLock.Path())
			warned = true
		}
		if lastLog.IsZero() || now.Sub(lastLog) >= p.ssoLockLog {
			p.ssoLogf("Waiting for SSO lock at %s", p.ssoTokenLock.Path())
			lastLog = now
		}

		if err = p.ssoSleep(ctx, p.ssoLockWait); err != nil {
			return nil, false, err
		}
	}
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

func ssoRetrySettings() (int, time.Duration, time.Duration) {
	return ssoMaxAttempts, ssoRetryBase, ssoRetryMax
}

func retryAfterFromError(err error) (time.Duration, bool) {
	var rspError *awshttp.ResponseError
	if errors.As(err, &rspError) {
		if rspError.Response != nil {
			if d, ok := parseRetryAfter(rspError.Response.Header.Get("Retry-After")); ok {
				return d, true
			}
		}
	}
	return 0, false
}

func parseRetryAfter(value string) (time.Duration, bool) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(trimmed); err == nil {
		if secs < 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if t, err := http.ParseTime(trimmed); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

func isSSORateLimitError(err error) bool {
	var tooMany *ssotypes.TooManyRequestsException
	if errors.As(err, &tooMany) {
		return true
	}
	var rspError *awshttp.ResponseError
	if errors.As(err, &rspError) && rspError.HTTPStatusCode() == http.StatusTooManyRequests {
		return true
	}
	return false
}

func jitterRetryAfter(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	return jitterDelay(base)
}

func jitteredBackoff(base, max time.Duration, attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	capDelay := base << uint(attempt-1)
	if capDelay > max {
		capDelay = max
	}
	if capDelay < base {
		capDelay = base
	}
	return jitterDelay(capDelay)
}

func jitterDelay(base time.Duration) time.Duration {
	if base <= 0 {
		return 0
	}
	min := ssoRetryAfterJitterMin
	max := ssoRetryAfterJitterMax
	if max < min {
		max = min
	}
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	factor := min + r.Float64()*(max-min)
	return time.Duration(float64(base) * factor)
}
