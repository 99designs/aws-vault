package mfa

import (
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/yawn/ykoath"
)

func init() {
	TokenProviders["yubikey"] = &YubikeyTokenProvider{}
}

type YubikeyTokenProvider struct {
	Serial string
}

func (y *YubikeyTokenProvider) GetToken() (otpToken string, err error) {
	defer func() {
		if err != nil {
			fmt.Printf("unable to get otp from yubikey: %s\n", err)

			// something went wrong with getting a token from a yubikey
			// fall back to terminal prompt
			tp := TokenProviders["terminal"]
			tp.SetSerial(y.Serial)
			otpToken, err = tp.GetToken()

		}
	}()

	token, err := NewYubikey()
	if err != nil {
		return "", err
	}

	otpToken, err = token.GetOTP(time.Now(), "AWS:"+y.Serial)
	if err != nil {
		return "", err
	}

	return otpToken, nil
}

func (y *YubikeyTokenProvider) SetSerial(mfaSerial string) {
	y.Serial = mfaSerial
}

func (y *YubikeyTokenProvider) GetSerial() string {
	return y.Serial
}

// Yubikey represents a Yubikey mfa device
type Yubikey struct {
	client *ykoath.OATH
	sync.Mutex
}

// NewIAMYubikey initializes a Yubikey
func NewYubikey() (*Yubikey, error) {
	oath, err := ykoath.New()

	if err != nil {
		return nil, fmt.Errorf("failed to initialize Yubikey: %w", err)
	}

	_, err = oath.Select()

	if err != nil {
		return nil, fmt.Errorf("failed to select OATH application in Yubikey: %w", err)
	}

	return &Yubikey{
		client: oath,
	}, nil

}

// GetOTP gets a new OTP from a Yubikey
func (y *Yubikey) GetOTP(now time.Time, name string) (string, error) {

	y.Lock()
	defer y.Unlock()

	defer func(prev func() time.Time) {
		y.client.Clock = prev
	}(y.client.Clock)

	y.client.Clock = func() time.Time {
		return now
	}

	var called bool
	touchRequiredCb := getTouchRequiredCallback(&called)
	code, err := y.client.Calculate(name, touchRequiredCb)
	if err == nil && called {
		os.Stderr.WriteString("OK\n")
	}
	return code, err
}

// getTouchRequiredCallback returns a function that prompts the use to touch the yubikey if touch is required. The
// called variable is used to tell if the function was called or not
func getTouchRequiredCallback(called *bool) func(string) error {
	return func(_ string) error {
		*called = true
		os.Stderr.WriteString("waiting for yubikey touch...\n")
		return nil
	}
}
