package command

import (
	"flag"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/aws/aws-sdk-go/aws"
	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/aws/aws-sdk-go/service/sts"
	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/mitchellh/cli"
	"github.com/99designs/aws-vault/keyring"
	"github.com/99designs/aws-vault/vault"
)

const (
	DefaultSessionDuration = time.Hour * 10
)

// Executes a subcommand with credentials passed to it via the environment
type ExecCommand struct {
	Ui cli.Ui

	// things passed in from main
	Keyring        keyring.Keyring
	MFASerial      string
	Env            []string
	DefaultProfile string

	// template functions for testing
	loadProfileFunc func(name string) (vault.AWSProfile, error)
	execFunc        func(cmd string, argv []string, env []string) error
}

func (c *ExecCommand) Run(args []string) int {
	var (
		refresh, noMfa, noSession, session bool
		profileName                        string
		sessionDuration                    time.Duration
	)
	flagSet := flag.NewFlagSet("exec", flag.ExitOnError)
	flagSet.StringVar(&profileName, "profile", c.DefaultProfile, "")
	flagSet.StringVar(&profileName, "p", c.DefaultProfile, "")
	flagSet.BoolVar(&session, "session", true, "")
	flagSet.DurationVar(&sessionDuration, "duration", DefaultSessionDuration, "")
	flagSet.BoolVar(&refresh, "refresh", false, "")
	flagSet.BoolVar(&noMfa, "no-mfa", false, "")
	flagSet.BoolVar(&noSession, "no-session", false, "")
	flagSet.Usage = func() { c.Ui.Output(c.Help()) }

	if err := flagSet.Parse(args); err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	cmdArgs := flagSet.Args()
	if len(cmdArgs) < 1 {
		c.Ui.Output(c.Help())
		return 1
	}

	if c.loadProfileFunc == nil {
		c.loadProfileFunc = vault.LoadAWSProfile
	}

	profile, err := c.loadProfileFunc(profileName)
	if err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	if !noMfa && profile.MFASerial != "" {
		c.MFASerial = profile.MFASerial
	}

	env := append(c.Env, "AWS_DEFAULT_PROFILE="+profileName)

	if session && !noSession {
		var sessionCreds *vault.SessionCredentials
		var err error
		var sourceProfile string = profileName

		if profile.SourceProfile != "" {
			sourceProfile = profile.SourceProfile
		}

		// look for cached session credentials first
		keyring.Unmarshal(c.Keyring, vault.SessionServiceName, profileName, &sessionCreds)

		// otherwise get fresh credentials
		if sessionCreds == nil || refresh || time.Now().After(*sessionCreds.Expiration) {
			if profile.RoleARN != "" {
				sessionCreds, err = c.assumeRole(sourceProfile, profile.RoleARN, sessionDuration)
				if err != nil {
					c.Ui.Error(err.Error())
					return 1
				}
			} else {
				sessionCreds, err = c.session(sourceProfile, sessionDuration)
				if err != nil {
					c.Ui.Error(err.Error())
					return 1
				}
			}

			// cache the session credentials for next time
			err = keyring.Marshal(c.Keyring, vault.SessionServiceName, profileName, sessionCreds)
			if err != nil {
				c.Ui.Error(err.Error())
				return 1
			}
		}

		env = append(env, "AWS_ACCESS_KEY_ID="+*sessionCreds.AccessKeyID)
		env = append(env, "AWS_SECRET_ACCESS_KEY="+*sessionCreds.SecretAccessKey)
		env = append(env, "AWS_SESSION_TOKEN="+*sessionCreds.SessionToken)
	} else {
		creds, err := c.credentials(profileName)
		if err != nil {
			c.Ui.Error(err.Error())
			return 1
		}

		env = append(env, creds.Environ()...)
	}

	if c.execFunc == nil {
		c.execFunc = c.exec
	}

	if err = c.execFunc(cmdArgs[0], cmdArgs, env); err != nil {
		c.Ui.Error(err.Error())
		return 1
	}

	return 0
}

func (c *ExecCommand) exec(cmd string, argv []string, env []string) error {
	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}

	return syscall.Exec(bin, argv, env)
}

func (c *ExecCommand) promptToken(MFASerial string) (string, error) {
	token, err := c.Ui.AskSecret(fmt.Sprintf("Enter token code for %q:", MFASerial))
	if err != nil {
		return "", err
	}
	c.Ui.Output("")
	return token, nil
}

func (c *ExecCommand) credentials(sourceProfile string) (*vault.Credentials, error) {
	var creds vault.Credentials
	if err := keyring.Unmarshal(c.Keyring, vault.ServiceName, sourceProfile, &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

func (c *ExecCommand) session(sourceProfile string, d time.Duration) (*vault.SessionCredentials, error) {
	creds, err := c.credentials(sourceProfile)
	if err != nil {
		return nil, err
	}
	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(int64(d.Seconds())),
	}
	if c.MFASerial != "" {
		token, err := c.promptToken(c.MFASerial)
		if err != nil {
			return nil, err
		}
		input.SerialNumber = aws.String(c.MFASerial)
		input.TokenCode = aws.String(token)
	}
	svc := sts.New(creds.AwsConfig())
	resp, err := svc.GetSessionToken(input)
	if err != nil {
		return nil, err
	}
	return &vault.SessionCredentials{resp.Credentials}, nil
}

func (c *ExecCommand) assumeRole(sourceProfile string, roleArn string, d time.Duration) (*vault.SessionCredentials, error) {
	creds, err := c.credentials(sourceProfile)
	if err != nil {
		return nil, err
	}
	input := &sts.AssumeRoleInput{
		RoleARN:         aws.String(roleArn),
		RoleSessionName: aws.String(sourceProfile),
		DurationSeconds: aws.Int64(int64(d.Seconds())),
	}
	if c.MFASerial != "" {
		token, err := c.promptToken(c.MFASerial)
		if err != nil {
			return nil, err
		}
		input.SerialNumber = aws.String(c.MFASerial)
		input.TokenCode = aws.String(token)
	}
	svc := sts.New(creds.AwsConfig())
	resp, err := svc.AssumeRole(input)
	if err != nil {
		return nil, err
	}
	return &vault.SessionCredentials{resp.Credentials}, nil
}

func (c *ExecCommand) Help() string {
	helpText := `
Usage: aws-vault exec [options] [cmd args...]
  Executes a command with the credentials from the given profile

Options:
  --profile=default         Which aws profile to use, defaults to $AWS_DEFAULT_PROFILE
  --[no-]session            Whether to generate an STS session [default: session]
  --duration=1h             The duration for the STS session generated
  --refresh                 Establish a new session, or refresh the existing one
`
	return strings.TrimSpace(helpText)
}

func (c *ExecCommand) Synopsis() string {
	return "Executes a command with the credentials from the given profile"
}
