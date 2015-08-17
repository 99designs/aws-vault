package command

import "github.com/99designs/aws-vault/vault"

type testSessionProvider struct {
	Creds vault.SessionCredentials
}

func (t *testSessionProvider) Session(conf vault.SessionConfig) (vault.SessionCredentials, error) {
	return t.Creds, nil
}
