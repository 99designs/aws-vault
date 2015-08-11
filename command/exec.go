package command

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/mitchellh/cli"
)

type ExecCommand struct {
	Ui      cli.Ui
	Keyring keyring.Keyring
}

func (c *ExecCommand) Run(args []string) int {
	var (
		sessionToken    bool
		sessionDuration time.Duration
	)
	config, err := parseFlags(args, func(f *flag.FlagSet) {
		f.BoolVar(&sessionToken, "session", true, "generate a session token via STS")
		f.DurationVar(&sessionDuration, "duration", time.Hour*1, "duration for session token")
		f.Usage = func() { c.Ui.Output(c.Help()) }
	})
	cmdArgs := config.Args()
	if len(cmdArgs) < 1 {
		c.Ui.Output(c.Help())
		return 1
	}
	b, err := c.Keyring.Get(vault.ServiceName, config.Profile)
	if err != nil {
		c.Ui.Error(err.Error())
		return 3
	}

	var creds vault.Credentials
	if err = json.Unmarshal(b, &creds); err != nil {
		c.Ui.Error(err.Error())
		return 4
	}

	bin, lookErr := exec.LookPath(cmdArgs[0])
	if lookErr != nil {
		c.Ui.Error(err.Error())
		return 5
	}

	env := os.Environ()

	if sessionToken {
		svc := sts.New(creds.AwsConfig())
		stsEnv, err := getSessionTokenEnviron(svc, sessionDuration)
		if err != nil {
			c.Ui.Error(err.Error())
			return 6
		}

		for _, val := range stsEnv {
			env = append(env, val)
		}

	} else {
		for _, val := range creds.Environ() {
			env = append(env, val)
		}
	}

	env = append(env, "AWS_DEFAULT_PROFILE="+config.Profile)
	execErr := syscall.Exec(bin, cmdArgs, env)
	if execErr != nil {
		c.Ui.Error(execErr.Error())
		return 6
	}

	return 0
}

func getSessionToken(svc *sts.STS, duration time.Duration) (*sts.Credentials, error) {
	params := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(duration.Seconds())),
	}
	resp, err := svc.GetSessionToken(params)
	if err != nil {
		return nil, err
	}

	return resp.Credentials, nil
}

func getSessionTokenEnviron(svc *sts.STS, duration time.Duration) ([]string, error) {
	creds, err := getSessionToken(svc, duration)
	if err != nil {
		return []string{}, err
	}

	return []string{
		"AWS_ACCESS_KEY_ID=" + *creds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + *creds.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + *creds.SessionToken,
	}, nil
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
