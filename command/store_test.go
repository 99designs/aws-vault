package command

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
)

func TestStoreCommand_implements(t *testing.T) {
	var _ cli.Command = &StoreCommand{}
}

func TestStoreCommandRunUsesDefault(t *testing.T) {
	ui := &cli.MockUi{InputReader: bytes.NewBufferString("ABC\nXYZ\n")}
	kr := &keyring.ArrayKeyring{}
	p := &vault.Profile{Name: "default"}

	c := &StoreCommand{Ui: ui, Keyring: kr, profileConfig: vault.NewProfileConfig(p)}
	code := c.Run([]string{})
	if code != 0 {
		fmt.Println(ui.OutputWriter.String())
		t.Fatalf("bad: %d. %#v", code, ui.ErrorWriter.String())
	}

	creds, err := p.Keyring(kr).Read()
	if err != nil {
		t.Fatal(err)
	}

	if creds.AccessKeyId != "ABC" {
		t.Fatalf("Unexpected AccessKeyId of %q", creds.AccessKeyId)
	}

	if creds.SecretKey != "XYZ" {
		t.Fatalf("Unexpected SecretKey of %q", creds.SecretKey)
	}
}
