package yubikey

import (
	"sync"
	"time"

	"github.com/99designs/aws-vault/mfa/device"
	"github.com/pkg/errors"
	"github.com/yawn/ykoath"
)

type touchRequiredCallback func(name string) error

// Yubikey is a ReaderManager based on a Yubikey.
type Yubikey struct {
	client *ykoath.OATH
	sync.Mutex
	touchRequiredCallback
}

// Ensure ReaderManager implemented.
var _ device.ReaderManager = &Yubikey{}

// New initializes a new Yubikey source.
func New(cb touchRequiredCallback) (*Yubikey, error) {

	oath, err := ykoath.New()

	if err != nil {
		return nil, errors.Wrapf(err, "failed to initialize Yubikey")
	}

	_, err = oath.Select()

	if err != nil {
		return nil, errors.Wrapf(err, "failed to select OATH application in Yubikey")
	}

	return &Yubikey{
		client:                oath,
		touchRequiredCallback: cb,
	}, nil

}

// Add adds / overwrites a credential to a Yubikey.
func (y *Yubikey) Add(name string, secret []byte) error {
	return y.client.Put(name, ykoath.HmacSha1, ykoath.Totp, 6, secret, y.touchRequiredCallback != nil)
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

	return y.client.Calculate(name, y.touchRequiredCallback)
}

// Name returns the name of this reader.
func (y *Yubikey) Name() string {
	return "yubikey (ykoath)"
}
