package keyring

type arrayKeyring struct {
	items map[string]Item
}

func (k *arrayKeyring) Get(key string) (Item, error) {
	if i, ok := k.items[key]; ok {
		return i, nil
	} else {
		return Item{}, ErrKeyNotFound
	}
}

func (k *arrayKeyring) Set(i Item) error {
	if k.items == nil {
		k.items = map[string]Item{}
	}
	k.items[i.Key] = i
	return nil
}

func (k *arrayKeyring) Remove(key string) error {
	delete(k.items, key)
	return nil
}

func (k *arrayKeyring) Keys() ([]string, error) {
	var keys = []string{}
	for key := range k.items {
		keys = append(keys, key)
	}
	return keys, nil
}
