package keyring

type ArrayKeyring struct {
	secrets map[string][]byte
}

var _ Keyring = &ArrayKeyring{}

func (k *ArrayKeyring) Get(key string) ([]byte, error) {
	if b, ok := k.secrets[key]; ok {
		return b, nil
	} else {
		return nil, ErrKeyNotFound
	}
}

func (k *ArrayKeyring) Set(key string, secret []byte) error {
	if k.secrets == nil {
		k.secrets = map[string][]byte{}
	}
	k.secrets[key] = secret
	return nil
}

func (k *ArrayKeyring) Remove(key string) error {
	delete(k.secrets, key)
	return nil
}

func (k *ArrayKeyring) Keys() ([]string, error) {
	var keys = []string{}
	for key := range k.secrets {
		keys = append(keys, key)
	}
	return keys, nil
}
