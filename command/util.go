package command

import "github.com/99designs/aws-vault/vault"

type sessionProvider interface {
	Session(conf vault.SessionConfig) (vault.SessionCredentials, error)
}

type profileConfig interface {
	Profile(name string) (*vault.Profile, error)
}
