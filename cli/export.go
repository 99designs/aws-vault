package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/99designs/aws-vault/v7/iso8601"
	"github.com/99designs/aws-vault/v7/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
	"github.com/aws/aws-sdk-go-v2/aws"
	ini "gopkg.in/ini.v1"
)

type ExportCommandInput struct {
	ProfileName     string
	Format          string
	Config          vault.Config
	SessionDuration time.Duration
	NoSession       bool
	UseStdout       bool
}

var (
	FormatTypeEnv        = "env"
	FormatTypeExportEnv  = "export-env"
	FormatTypeExportJSON = "json"
	FormatTypeExportINI  = "ini"
)

func ConfigureExportCommand(app *kingpin.Application, a *AwsVault) {
	input := ExportCommandInput{}

	cmd := app.Command("export", "Export AWS credentials.")

	cmd.Flag("duration", "Duration of the temporary or assume-role session. Defaults to 1h").
		Short('d').
		DurationVar(&input.SessionDuration)

	cmd.Flag("no-session", "Skip creating STS session with GetSessionToken").
		Short('n').
		BoolVar(&input.NoSession)

	cmd.Flag("region", "The AWS region").
		StringVar(&input.Config.Region)

	cmd.Flag("mfa-token", "The MFA token to use").
		Short('t').
		StringVar(&input.Config.MfaToken)

	cmd.Flag("format", fmt.Sprintf("Format to output credentials. Valid values are %s, %s and %s", FormatTypeEnv, FormatTypeExportEnv, FormatTypeExportJSON)).
		Default(FormatTypeEnv).
		EnumVar(&input.Format, FormatTypeEnv, FormatTypeExportEnv, FormatTypeExportJSON, FormatTypeExportINI)

	cmd.Flag("stdout", "Print the SSO link to the terminal without automatically opening the browser").
		BoolVar(&input.UseStdout)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		input.Config.MfaPromptMethod = a.PromptDriver(false)
		input.Config.NonChainedGetSessionTokenDuration = input.SessionDuration
		input.Config.AssumeRoleDuration = input.SessionDuration
		input.Config.SSOUseStdout = input.UseStdout

		f, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}

		err = ExportCommand(input, f, keyring)
		app.FatalIfError(err, "exec")
		return nil
	})
}

func ExportCommand(input ExportCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) error {
	if os.Getenv("AWS_VAULT") != "" {
		return fmt.Errorf("in an existing aws-vault subshell; 'exit' from the subshell or unset AWS_VAULT to force")
	}

	vault.UseSession = !input.NoSession

	config, err := vault.NewConfigLoader(input.Config, f, input.ProfileName).LoadFromProfile(input.ProfileName)
	if err != nil {
		return fmt.Errorf("Error loading config: %w", err)
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring}
	credsProvider, err := vault.NewTempCredentialsProvider(config, ckr)
	if err != nil {
		return fmt.Errorf("Error getting temporary credentials: %w", err)
	}

	if input.Format == FormatTypeExportJSON {
		return printJSON(input, credsProvider)
	} else if input.Format == FormatTypeExportINI {
		return printINI(credsProvider, input.ProfileName, config.Region)
	} else if input.Format == FormatTypeExportEnv {
		return printEnv(input, credsProvider, config.Region, "export ")
	} else {
		return printEnv(input, credsProvider, config.Region, "")
	}
}

func printJSON(input ExportCommandInput, credsProvider aws.CredentialsProvider) error {
	// AwsCredentialHelperData is metadata for AWS CLI credential process
	// See https://docs.aws.amazon.com/cli/latest/topic/config-vars.html#sourcing-credentials-from-external-processes
	type AwsCredentialHelperData struct {
		Version         int    `json:"Version"`
		AccessKeyID     string `json:"AccessKeyId"`
		SecretAccessKey string `json:"SecretAccessKey"`
		SessionToken    string `json:"SessionToken,omitempty"`
		Expiration      string `json:"Expiration,omitempty"`
	}

	creds, err := credsProvider.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", input.ProfileName, err)
	}

	credentialData := AwsCredentialHelperData{
		Version:         1,
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
	}

	if creds.CanExpire {
		credentialData.Expiration = iso8601.Format(creds.Expires)
	}

	json, err := json.MarshalIndent(&credentialData, "", "  ")
	if err != nil {
		return fmt.Errorf("Error creating credential json: %w", err)
	}

	fmt.Print(string(json) + "\n")

	return nil
}

func mustNewKey(s *ini.Section, name, val string) {
	if val != "" {
		_, err := s.NewKey(name, val)
		if err != nil {
			log.Fatalln("Failed to create ini key:", err.Error())
		}
	}
}

func printINI(credsProvider aws.CredentialsProvider, profilename, region string) error {
	creds, err := credsProvider.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", profilename, err)
	}

	f := ini.Empty()
	s, err := f.NewSection("profile " + profilename)
	if err != nil {
		return fmt.Errorf("Failed to create ini section: %w", err)
	}

	mustNewKey(s, "aws_access_key_id", creds.AccessKeyID)
	mustNewKey(s, "aws_secret_access_key", creds.SecretAccessKey)
	mustNewKey(s, "aws_session_token", creds.SessionToken)
	if creds.CanExpire {
		mustNewKey(s, "aws_credential_expiration", iso8601.Format(creds.Expires))
	}
	mustNewKey(s, "region", region)

	_, err = f.WriteTo(os.Stdout)
	if err != nil {
		return fmt.Errorf("Failed to output ini: %w", err)
	}

	return nil
}

func printEnv(input ExportCommandInput, credsProvider aws.CredentialsProvider, region, prefix string) error {
	creds, err := credsProvider.Retrieve(context.TODO())
	if err != nil {
		return fmt.Errorf("Failed to get credentials for %s: %w", input.ProfileName, err)
	}

	fmt.Printf("%sAWS_ACCESS_KEY_ID=%s\n", prefix, creds.AccessKeyID)
	fmt.Printf("%sAWS_SECRET_ACCESS_KEY=%s\n", prefix, creds.SecretAccessKey)

	if creds.SessionToken != "" {
		fmt.Printf("%sAWS_SESSION_TOKEN=%s\n", prefix, creds.SessionToken)
	}
	if creds.CanExpire {
		fmt.Printf("%sAWS_CREDENTIAL_EXPIRATION=%s\n", prefix, iso8601.Format(creds.Expires))
	}
	if region != "" {
		fmt.Printf("%sAWS_REGION=%s\n", prefix, region)
		fmt.Printf("%sAWS_DEFAULT_REGION=%s\n", prefix, region)
	}

	return nil
}
