go-osxkeychain
==============

[![GoDoc](http://godoc.org/github.com/99designs/go-osxkeychain?status.png)](http://godoc.org/github.com/99designs/go-osxkeychain)

A golang binding for the [OSX Keychain Service API](https://developer.apple.com/library/mac/documentation/Security/Reference/keychainservices/index.html).

## Usage

```go
	attributes := osxkeychain.GenericPasswordAttributes{
		ServiceName: "my service",
		AccountName: "my account",
		Password: []byte("password123"),
	}

	// Add the item
	err := osxkeychain.AddGenericPassword(&attributes)
	if err != nil {
		log.Fatal(err)
	}

	// Look it up subsequently
	password, err := FindGenericPassword(&attributes)
	if err != nil {
		t.Error(err)
	}
```