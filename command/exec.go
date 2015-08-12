package command

import (
	"encoding/json"
	"flag"
	"fmt"
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
		session, noSession bool
		sessionDuration    time.Duration
		mfa, noMfa         bool
	)
	config, err := parseFlags(args, func(f *flag.FlagSet) {
		f.BoolVar(&session, "session", true, "generate a session token via STS")
		f.BoolVar(&noSession, "no-session", false, "generate a session token via STS")
		f.DurationVar(&sessionDuration, "duration", time.Hour*1, "duration for session token")
		f.BoolVar(&mfa, "mfa", true, "prompt for an mfa token if needed")
		f.BoolVar(&noMfa, "no-mfa", false, "don't prompt for an mfa token")
		f.Usage = func() { c.Ui.Output(c.Help()) }
	})
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	cmdArgs := config.Args()
	if len(cmdArgs) < 1 {
		c.Ui.Output(c.Help())
		return 1
	}
	b, err := c.Keyring.Get(vault.ServiceName, config.Profile)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	profiles, err := vault.LoadAWSProfiles()
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	profile, ok := profiles[config.Profile]
	if !ok {
		c.Ui.Error("Unknown profile " + config.Profile)
		return 1
	}

	env := os.Environ()
	env = append(env, "AWS_DEFAULT_PROFILE="+config.Profile)

	var creds vault.Credentials
	if err = json.Unmarshal(b, &creds); err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	bin, lookErr := exec.LookPath(cmdArgs[0])
	if lookErr != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	if session && !noSession {
		svc := sts.New(creds.AwsConfig())

		params := &sts.GetSessionTokenInput{
			DurationSeconds: aws.Int64(int64(sessionDuration.Seconds())),
		}

		if mfa && !noMfa && profile.MFASerial != "" {
			token, err := c.Ui.AskSecret(fmt.Sprintf("Enter token code for %q:", profile.MFASerial))
			if err != nil {
				c.Ui.Error(err.Error())
				return 1
			}
			c.Ui.Output("")
			params.SerialNumber = aws.String(profile.MFASerial)
			params.TokenCode = aws.String(token)
		}

		resp, err := svc.GetSessionToken(params)
		if err != nil {
			c.Ui.Error(err.Error())
			return 1
		}

		for _, val := range sessionTokenEnviron(resp.Credentials) {
			env = append(env, val)
		}

	} else {
		for _, val := range creds.Environ() {
			env = append(env, val)
		}
	}

	execErr := syscall.Exec(bin, cmdArgs, env)
	if execErr != nil {
		c.Ui.Error(execErr.Error())
		return 6
	}

	return 0
}

func sessionTokenEnviron(creds *sts.Credentials) []string {
	return []string{
		"AWS_ACCESS_KEY_ID=" + *creds.AccessKeyID,
		"AWS_SECRET_ACCESS_KEY=" + *creds.SecretAccessKey,
		"AWS_SESSION_TOKEN=" + *creds.SessionToken,
	}
}

func (c *ExecCommand) Help() string {
	helpText := `
Usage: aws-vault exec [options] [cmd args...]
  Executes a command with the credentials from the given profile

Options:
  --profile=default         Which aws profile to use, defaults to $AWS_DEFAULT_PROFILE
  --[no-]session            Whether to generate an STS session [default: session]
  --duration=1h             The duration for the STS session generated
`
	return strings.TrimSpace(helpText)
}

func (c *ExecCommand) Synopsis() string {
	return "Executes a command with the credentials from the given profile"
}
