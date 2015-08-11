package command

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
	"github.com/mitchellh/cli"
)

type ExecCommand struct {
	Ui      cli.Ui
	Keyring keyring.Keyring
}

func (c *ExecCommand) Run(args []string) int {
	cmdFlags := flag.NewFlagSet("exec", flag.ContinueOnError)
	cmdFlags.Usage = func() { c.Ui.Output(c.Help()) }
	if err := cmdFlags.Parse(args); err != nil {
		return 1
	}
	cmdArgs := cmdFlags.Args()
	if len(cmdArgs) < 2 {
		c.Ui.Error("Expected more arguments")
		c.Ui.Output(c.Help())
		return 1
	}
	b, err := c.Keyring.Get(vault.ServiceName, cmdArgs[0])
	if err != nil {
		c.Ui.Error(err.Error())
		return 3
	}

	var creds vault.Credentials
	if err = json.Unmarshal(b, &creds); err != nil {
		c.Ui.Error(err.Error())
		return 4
	}

	bin, lookErr := exec.LookPath(cmdArgs[1])
	if lookErr != nil {
		c.Ui.Error(err.Error())
		return 5
	}

	env := os.Environ()
	for _, val := range creds.Environ() {
		env = append(env, val)
	}

	execErr := syscall.Exec(bin, cmdArgs[2:], env)
	if execErr != nil {
		c.Ui.Error(execErr.Error())
		return 6
	}

	return 0
}

func (c *ExecCommand) Help() string {
	helpText := `
Usage: aws-vault exec <keyname> <cmd> [cmd args...]
  Executes a command with the named keys in the environment
`
	return strings.TrimSpace(helpText)
}

func (c *ExecCommand) Synopsis() string {
	return "Executes a command with the named keys in the environment"
}
