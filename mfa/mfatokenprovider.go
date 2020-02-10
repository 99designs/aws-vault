package mfa

import (
	"fmt"
)

// TokenProvider is an interface to provide an mfa token. It's intended that providers do whatever is necessary to get
// a token, eg prompt the use via the terminal or fetch it from a yubikey.
type TokenProvider interface {
	Retrieve(mfaSerial string) (string, error)
}

func defaultPrompt(mfaSerial string) string {
	return fmt.Sprintf("Enter token for %s: ", mfaSerial)
}

var TokenProviders = map[string]TokenProvider{
	"terminal": Terminal{},
}

func TokenProvidersAvailable() []string {
	providers := []string{}
	for k := range TokenProviders {
		providers = append(providers, k)
	}
	return providers
}

func GetTokenProvider(s string) TokenProvider {
	p, found := TokenProviders[s]
	if !found {
		panic(fmt.Sprintf("Prompt method %q doesn't exist", s))
	}

	return p
}
