package vault

import "github.com/99designs/aws-vault/keyring"

const (
	ServiceName        = "aws-vault"
	SessionServiceName = "aws-vault.sessions"
)

type ProfileKeyring struct {
	kr      keyring.Keyring
	profile *Profile
}

func (pk *ProfileKeyring) Read() (Credentials, error) {
	var sourceProfile string = pk.profile.Name
	if pk.profile.SourceProfile != nil {
		sourceProfile = pk.profile.SourceProfile.Name
	}
	var creds Credentials
	err := keyring.Unmarshal(pk.kr, ServiceName, sourceProfile, &creds)
	return creds, err
}

func (pk *ProfileKeyring) Store(c Credentials) error {
	return keyring.Marshal(pk.kr, ServiceName, pk.profile.Name, &c)
}

func (pk *ProfileKeyring) ReadSession() (SessionCredentials, error) {
	var sourceProfile string = pk.profile.Name
	if pk.profile.SourceProfile != nil {
		sourceProfile = pk.profile.SourceProfile.Name
	}
	var creds SessionCredentials
	err := keyring.Unmarshal(pk.kr, SessionServiceName, sourceProfile, &creds)
	return creds, err
}

func (pk *ProfileKeyring) StoreSession(c SessionCredentials) error {
	return keyring.Marshal(pk.kr, SessionServiceName, pk.profile.Name, &c)
}
