package mfa

import (
	"fmt"
	"os/exec"
)

func init() {
	TokenProviders["ykman"] = &YkMan{}
}

type YkMan struct {
	Serial string
}

func (y *YkMan) GetToken() (otpToken string, err error) {
	defer func() {
		if err != nil {
			fmt.Printf("unable to get otp from ykman: %s\n", err)

			// something went wrong with getting a token from a ykman
			// fall back to terminal prompt
			tp := TokenProviders["terminal"]
			tp.SetSerial(y.Serial)
			otpToken, err = tp.GetToken()

		}
	}()

	cmd := exec.Command("ykman", "oath", "code", "-s", y.Serial)
	var out []byte
	out, err = cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out[:len(out)-1]), nil
}

func (y *YkMan) SetSerial(mfaSerial string) {
	y.Serial = mfaSerial
}

func (y *YkMan) GetSerial() string {
	return y.Serial
}
