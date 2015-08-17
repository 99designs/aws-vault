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

func shellCmds(cmdToWrap string) (profileFile, aliasCmd, evalCmd string, err error) {
	shell := filepath.Base(os.Getenv("SHELL"))

	aliasCmd = fmt.Sprintf(`alias %s="aws-vault exec %s"`, cmdToWrap, cmdToWrap)
	evalCmd = fmt.Sprintf(`eval "$(aws-vault alias -s %s)"`, cmdToWrap)

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
	var cmdToWrap string

	config, err := parseFlags(args, func(f *flag.FlagSet) {
		f.BoolVar(&aliasScript, "s", false, "outputs shell script suitable for eval")
		f.Usage = func() { c.Ui.Output(c.Help()) }
	})
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	cmdArgs := config.Args()
	if len(cmdArgs) > 1 {
		c.Ui.Error("alias can only wrap a single command")
		return 1
	} else if len(cmdArgs) > 0 {
		cmdToWrap = config.Arg(0)
	} else {
		cmdToWrap = "aws"
	}

	profileFile, aliasCmd, evalCmd, err := shellCmds(cmdToWrap)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	if aliasScript {
		c.Ui.Info(aliasCmd)
	} else {
		c.Ui.Info(fmt.Sprintf(
			"# Wrap %s automatically by adding the following to %s:\n%s",
			cmdToWrap,
			profileFile,
			evalCmd,
		))
	}

	return 0
}

func (c *AliasCommand) Help() string {
	helpText := `
Usage: aws-vault alias [-s] [cmd]
  Shows shell instructions for wrapping a command (by default aws). With -s, outputs shell script suitable for eval.
`
	return strings.TrimSpace(helpText)
}

func (c *AliasCommand) Synopsis() string {
	return "Shows shell instructions for wrapping a command"
}
