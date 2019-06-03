package yubikey

import (
	"os"
	"sync"
	"time"

	"github.com/99designs/aws-vault/mfa/device"
	"github.com/pkg/errors"
	"github.com/yawn/ykoath"
)

// Yubikey is a ReaderManager based on a Yubikey.
type Yubikey struct {
	client *ykoath.OATH
	sync.Mutex
	AddOptions AddOptions
}

// AddOptions configure Add() behaviour.
type AddOptions struct {
	requireTouch bool
}

// Ensure ReaderManager implemented.
var _ device.ReaderManager = &Yubikey{}

// New initializes a new Yubikey source.
func New() (*Yubikey, error) {
	oath, err := ykoath.New()

	if err != nil {
		return nil, errors.Wrapf(err, "failed to initialize Yubikey")
	}

	_, err = oath.Select()

	if err != nil {
		return nil, errors.Wrapf(err, "failed to select OATH application in Yubikey")
	}

	return &Yubikey{
		client:     oath,
		AddOptions: AddOptions{},
	}, nil

}

// RequireAddTouch sets whether a touch is required to provide a otp.
func (y *Yubikey) RequireAddTouch(requireTouch bool) *Yubikey {
	y.AddOptions.requireTouch = requireTouch
	return y
}

// Add adds / overwrites a credential to a Yubikey.
func (y *Yubikey) Add(name string, secret []byte) error {
	return y.client.Put(name, ykoath.HmacSha1, ykoath.Totp, 6, secret, y.AddOptions.requireTouch)
}

// Delete deletes a credential from a Yubikey.
func (y *Yubikey) Delete(name string) error {
	return y.client.Delete(name)
}

// GetOTP gets a new OTP from a Yubikey.
func (y *Yubikey) GetOTP(now time.Time, name string) (string, error) {

	y.Lock()
	defer y.Unlock()

	defer func(prev func() time.Time) {
		y.client.Clock = prev
	}(y.client.Clock)

	y.client.Clock = func() time.Time {
		return now
	}

	code, err := y.client.Calculate(name, touchRequiredCallback)
	if err == nil && y.AddOptions.requireTouch {
		os.Stderr.WriteString("OK\n")
	}
	return code, err
}

// Name returns the name of this reader.
func (y *Yubikey) Name() string {
	return "yubikey (ykoath)"
}

func touchRequiredCallback(name string) error {
	os.Stderr.WriteString("waiting for yubikey touch...\n")
	return nil
}
