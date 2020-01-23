package mfa

type KnownToken struct {
	Token string
}

func (k KnownToken) Retrieve(_ string) (string, error) {
	return k.Token, nil
}
