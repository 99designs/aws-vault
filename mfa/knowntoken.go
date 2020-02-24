package mfa

type KnownToken struct {
	Token  string
	Serial string
}

func (k *KnownToken) GetToken() (string, error) {
	return k.Token, nil
}

func (k *KnownToken) SetSerial(mfaSerial string) {
	k.Serial = mfaSerial
}

func (k *KnownToken) GetSerial() string {
	return k.Serial
}
