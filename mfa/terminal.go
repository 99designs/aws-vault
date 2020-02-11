package mfa

import (
	"github.com/99designs/aws-vault/prompt"
)

type Terminal struct {
	Serial string
}

func (t *Terminal) GetToken() (string, error) {
	return prompt.TerminalPrompt(defaultPrompt(t.Serial))
}

func (t *Terminal) SetSerial(mfaSerial string) {
	t.Serial = mfaSerial
}

func (t *Terminal) GetSerial() string {
	return t.Serial
}
