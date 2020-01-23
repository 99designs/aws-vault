package mfa

import (
	"github.com/99designs/aws-vault/prompt"
)

type Terminal struct{}

func (t Terminal) Retrieve(mfaSerial string) (string, error) {
	return prompt.TerminalPrompt(defaultPrompt(mfaSerial))
}
