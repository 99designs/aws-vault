package mfa

import (
	"fmt"
	"os/exec"

	"github.com/99designs/aws-vault/prompt"
)

func init() {
	TokenProviders["ykman"] = YkMan{}
}

type YkMan struct{}

func (t YkMan) Retrieve(mfaSerial string) (otpToken string, err error) {
	defer func() {
		if err != nil {
			fmt.Printf("unable to get otp from ykman: %s\n", err)

			// something went wrong with getting a token from a ykman
			// fall back to terminal prompt
			otpToken, err = prompt.TerminalPrompt(defaultPrompt(mfaSerial))

		}
	}()

	cmd := exec.Command("ykman", "oath", "code", "-s", mfaSerial)
	var out []byte
	out, err = cmd.Output()
	if err != nil {
		return "", err
	}
	return string(out[:len(out)-1]), nil
}
