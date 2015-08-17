package command

import (
	"strings"
	"testing"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/keyring"
)

func TestListCommand_implements(t *testing.T) {
	var _ cli.Command = &ListCommand{}
}

func TestListCommandRun(t *testing.T) {
	ui := new(cli.MockUi)
	kr := &keyring.ArrayKeyring{}

	if err := storeCredentials(kr, "llamas", "ABCDEFG", "XYZ"); err != nil {
		t.Fatal(err)
	}

	c := &ListCommand{Ui: ui, Keyring: kr}
	args := []string{}
	code := c.Run(args)
	if code != 0 {
		t.Fatalf("bad: %d. %#v", code, ui.ErrorWriter.String())
	}

	if !strings.Contains(ui.OutputWriter.String(), "llamas") {
		t.Fatalf("bad: %#v", ui.OutputWriter.String())
	}
}
