package command

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
)

type AliasCommand struct {
	Ui cli.Ui
}

func shellCmds() (profileFile, aliasCmd, evalCmd string, err error) {
	shell := filepath.Base(os.Getenv("SHELL"))

	aliasCmd = "alias aws='aws-vault exec $(which aws)'"
	evalCmd = `eval "$(aws-vault alias -s)"`

	switch shell {
	case "bash":
		profileFile = "~/.bash_profile"
	case "zsh":
		profileFile = "~/.zshrc"
	default:
		err = fmt.Errorf("Unsupported shell\nsupported shells: bash, zsh")
	}

	return
}

func (c *AliasCommand) Run(args []string) int {
	var aliasScript bool

	_, err := parseFlags(args, func(f *flag.FlagSet) {
		f.BoolVar(&aliasScript, "s", false, "outputs shell script suitable for eval")
		f.Usage = func() { c.Ui.Output(c.Help()) }
	})
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	profileFile, aliasCmd, evalCmd, err := shellCmds()
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	if aliasScript {
		c.Ui.Info(aliasCmd)
	} else {
		c.Ui.Info(fmt.Sprintf("# Wrap aws automatically by adding the following to %s:\n", profileFile))
		c.Ui.Info(evalCmd)
	}

	return 0
}

func (c *AliasCommand) Help() string {
	helpText := `
Usage: aws-vault alias
  Shows shell instructions for wrapping aws. With -s, outputs shell script suitable for eval.
`
	return strings.TrimSpace(helpText)
}

func (c *AliasCommand) Synopsis() string {
	return "Shows shell instructions for wrapping aws"
}
