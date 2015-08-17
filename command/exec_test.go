package command

import (
	"testing"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
)

func TestExecCommand_implements(t *testing.T) {
	var _ cli.Command = &ExecCommand{}
}

func TestExecCommandRun(t *testing.T) {
	ui := new(cli.MockUi)
	c := &ExecCommand{
		Ui: ui, sessionProvider: &fakeSessionProvider{},
	}
	args := []string{"true"}
	code := c.Run(args)
	if code != 0 {
		t.Fatalf("bad: %d. %#v", code, ui.ErrorWriter.String())
	}
}
