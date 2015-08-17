package command

import (
	"strings"
	"testing"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
)

func TestExecCommand_implements(t *testing.T) {
	var _ cli.Command = &ExecCommand{}
}

func TestExecCommandRun(t *testing.T) {
	ui := new(cli.MockUi)
	kr := &keyring.ArrayKeyring{}
	p := &vault.Profile{Name: "llamas"}

	if err := p.Keyring(kr).Store(vault.Credentials{"ABCDEFG", "XYZ"}); err != nil {
		t.Fatal(err)
	}

	c := &ExecCommand{
		Ui:              ui,
		Keyring:         kr,
		sessionProvider: &testSessionProvider{},
		profileConfig:   vault.NewProfileConfig(p),
	}
	code := c.Run([]string{"-profile", "llamas", "true"})
	if code != 0 {
		t.Fatalf("bad: %d. %#v", code, ui.ErrorWriter.String())
	}
}

func TestExecCommandRunWithMissingProfile(t *testing.T) {
	ui := new(cli.MockUi)
	kr := &keyring.ArrayKeyring{}

	c := &ExecCommand{
		Ui:              ui,
		Keyring:         kr,
		sessionProvider: &testSessionProvider{},
		profileConfig:   vault.NewProfileConfig(),
	}

	code := c.Run([]string{"-profile", "llamas", "true"})
	if code != 1 {
		t.Fatalf("bad: %d. %#v", code, ui.ErrorWriter.String())
	}

	if !strings.Contains(ui.OutputWriter.String(), "Profile 'llamas' not found") {
		t.Fatalf("bad: %#v", ui.OutputWriter.String())
	}
}
