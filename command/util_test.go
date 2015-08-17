package command

import "github.com/99designs/aws-vault/vault"

type fakeSessionProvider struct {
}

func (f *fakeSessionProvider) Session(conf vault.SessionConfig) (vault.SessionCredentials, error) {
	return vault.SessionCredentials{}, nil
}
