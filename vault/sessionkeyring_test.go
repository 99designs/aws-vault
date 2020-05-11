package vault_test

import (
	"testing"

	"github.com/99designs/aws-vault/v6/vault"
)

func TestIsSessionKey(t *testing.T) {
	var testCases = []struct {
		Key       string
		IsSession bool
	}{
		{"blah", false},
		{"blah session (61633665646639303539)", true},
		{"blah-iam session (32383863333237616430)", true},
		{"session,c2Vzc2lvbg,,1572281751", true},
		{"session,c2Vzc2lvbg,YXJuOmF3czppYW06OjEyMzQ1Njc4OTA6bWZhL2pzdGV3bW9u,1572281751", true},
	}

	for _, tc := range testCases {
		if tc.IsSession && !vault.IsSessionKey(tc.Key) {
			t.Fatalf("%q is a session key, but wasn't detected as one", tc.Key)
		} else if !tc.IsSession && vault.IsSessionKey(tc.Key) {
			t.Fatalf("%q isn't a session key, but was detected as one", tc.Key)
		}
	}
}
