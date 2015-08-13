package command

import (
	"strings"
	"testing"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
)

func TestExecCommandImplementsCommand(t *testing.T) {
	var _ cli.Command = &ExecCommand{}
}

func TestExecCommandRun(t *testing.T) {
	ui := new(cli.MockUi)
	c := &ExecCommand{Ui: ui}
	args := []string{"", ""}

	code := c.Run(args)
	if code != 0 {
		t.Fatalf("bad: %d. %#v", code, ui.ErrorWriter.String())
	}

	if !strings.Contains(ui.OutputWriter.String(), "llamas") {
		t.Fatalf("bad: %#v", ui.OutputWriter.String())
	}
}
