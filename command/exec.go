package command

import (
	"flag"
	"fmt"
	"log"
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
		duration           time.Duration
		noMfa              bool
	)
	config, err := parseFlags(args, func(f *flag.FlagSet) {
		f.BoolVar(&session, "session", true, "generate a session token via STS")
		f.BoolVar(&noSession, "no-session", false, "generate a session token via STS")
		f.DurationVar(&duration, "duration", time.Hour*1, "duration for session token")
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

	profile, err := vault.LoadAWSProfile(config.Profile)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	if noMfa {
		profile.MFASerial = ""
	}

	env := os.Environ()
	env = append(env, "AWS_DEFAULT_PROFILE="+config.Profile)

	bin, lookErr := exec.LookPath(cmdArgs[0])
	if lookErr != nil {
		c.Ui.Error(lookErr.Error())
		return 1
	}

	if session && !noSession {
		var sessionCreds *sts.Credentials
		var err error
		var sourceProfile string = config.Profile

		if profile.SourceProfile != "" {
			sourceProfile = profile.SourceProfile
		}

		// look for cached session credentials first
		keyring.Unmarshal(c.Keyring, vault.SessionServiceName, config.Profile, &sessionCreds)

		// otherwise get fresh credentials
		if sessionCreds == nil || time.Now().After(*sessionCreds.Expiration) {
			if profile.RoleARN != "" {
				sessionCreds, err = c.roleCredentials(sourceProfile, profile.RoleARN, profile.MFASerial, duration)
				if err != nil {
					c.Ui.Error(err.Error())
					return 1
				}
			} else {
				sessionCreds, err = c.sessionCredentials(sourceProfile, profile.MFASerial, duration)
				if err != nil {
					c.Ui.Error(err.Error())
					return 1
				}
			}

			// cache the session credentials for next time
			err = keyring.Marshal(c.Keyring, vault.SessionServiceName, config.Profile, sessionCreds)
			if err != nil {
				c.Ui.Error(err.Error())
				return 1
			}
		}

		env = append(env, "AWS_ACCESS_KEY_ID="+*sessionCreds.AccessKeyID)
		env = append(env, "AWS_SECRET_ACCESS_KEY="+*sessionCreds.SecretAccessKey)
		env = append(env, "AWS_SESSION_TOKEN="+*sessionCreds.SessionToken)
	} else {
		creds, err := c.credentials(config.Profile)
		if err != nil {
			c.Ui.Error(err.Error())
			return 1
		}

		env = append(env, creds.Environ()...)
	}

	execErr := syscall.Exec(bin, cmdArgs, env)
	if execErr != nil {
		c.Ui.Error(execErr.Error())
		return 6
	}

	return 0
}

func (c *ExecCommand) credentials(profile string) (*vault.Credentials, error) {
	var creds vault.Credentials
	if err := keyring.Unmarshal(c.Keyring, vault.ServiceName, profile, &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

func (c *ExecCommand) sessionCredentials(profile string, serial string, d time.Duration) (*sts.Credentials, error) {
	creds, err := c.credentials(profile)
	if err != nil {
		return nil, err
	}
	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(d.Seconds())),
	}
	err = c.promptMfa(serial, func(token string) {
		input.SerialNumber = aws.String(serial)
		input.TokenCode = aws.String(token)
	})
	if err != nil {
		return nil, err
	}
	svc := sts.New(creds.AwsConfig())
	resp, err := svc.GetSessionToken(input)
	if err != nil {
		return nil, err
	}
	return resp.Credentials, nil
}

func (c *ExecCommand) roleCredentials(profile string, roleArn string, serial string, d time.Duration) (*sts.Credentials, error) {
	creds, err := c.credentials(profile)
	if err != nil {
		return nil, err
	}
	input := &sts.AssumeRoleInput{
		RoleARN:         aws.String(roleArn), // Required
		RoleSessionName: aws.String(profile), // Required
		DurationSeconds: aws.Int64(int64(d.Seconds())),
	}
	err = c.promptMfa(serial, func(token string) {
		input.SerialNumber = aws.String(serial)
		input.TokenCode = aws.String(token)
	})
	if err != nil {
		return nil, err
	}
	svc := sts.New(creds.AwsConfig())
	resp, err := svc.AssumeRole(input)
	if err != nil {
		return nil, err
	}
	log.Printf("%#v", resp)
	return resp.Credentials, nil
}

func (c *ExecCommand) promptMfa(SerialNumber string, f func(token string)) error {
	if SerialNumber != "" {
		token, err := c.Ui.AskSecret(fmt.Sprintf("Enter token code for %q:", SerialNumber))
		if err != nil {
			return err
		}
		c.Ui.Output("")
		f(token)
	}
	return nil
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
