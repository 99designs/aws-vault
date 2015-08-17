package keyring

type ArrayKeyring struct {
	secrets map[string]map[string][]byte
}

func (k *ArrayKeyring) Get(service, key string) ([]byte, error) {
	if b, ok := k.secrets[service][key]; ok {
		return b, nil
	} else {
		return nil, ErrKeyNotFound
	}
}

func (k *ArrayKeyring) Set(service, key string, secret []byte) error {
	k.secrets[service][key] = secret
	return nil
}

func (k *ArrayKeyring) Remove(service, key string) error {
	if service, ok := k.secrets[service]; !ok {
		return ErrKeyNotFound
	} else {
		delete(service, key)
	}
	return nil
}

func (k *ArrayKeyring) List(service string) ([]string, error) {
	if serviceSecrets, ok := k.secrets[service]; !ok {
		return nil, ErrKeyNotFound
	} else {
		var keys = []string{}
		for key := range serviceSecrets {
			keys = append(keys, key)
		}
		return keys, nil
	}
}
