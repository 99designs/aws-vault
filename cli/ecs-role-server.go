package cli

import (
	"fmt"
	"time"

	"github.com/99designs/aws-vault/v6/server"
	"github.com/99designs/aws-vault/v6/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
)

type EcsServerCommandInput struct {
	ProfileName     string
	Config          vault.Config
	AuthToken       string
	Port            int
	SessionDuration time.Duration
}

func ConfigureEcsRoleServerCommand(app *kingpin.Application, a *AwsVault) {
	input := EcsServerCommandInput{}

	cmd := app.Command("ecs-role-server", "Starts a standalone ECS credential server")

	cmd.Arg("profile", "Name of the source profile").
		Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)
	cmd.Flag("auth-token", "Token required in the Authorization header of the request").
		Envar("AWS_VAULT_ECS_ROLE_SERVER_AUTH_TOKEN").
		StringVar(&input.AuthToken)
	cmd.Flag("port", "Port to listen on").
		Short('p').
		IntVar(&input.Port)
	cmd.Flag("duration", "Duration of the session").
		Short('d').
		Default("15m").
		DurationVar(&input.SessionDuration)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		input.Config.MfaPromptMethod = a.PromptDriver
		input.Config.AssumeRoleDuration = input.SessionDuration

		f, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}

		err = EcsRoleServerCommand(input, f, keyring)
		app.FatalIfError(err, "ecs-server")
		return nil
	})
}

func EcsRoleServerCommand(input EcsServerCommandInput, f *vault.ConfigFile, keyring keyring.Keyring) error {
	configLoader := vault.ConfigLoader{
		File:          f,
		BaseConfig:    input.Config,
		ActiveProfile: input.ProfileName,
	}
	config, err := configLoader.LoadFromProfile(input.ProfileName)
	if err != nil {
		return fmt.Errorf("Error loading config: %w", err)
	}

	ckr := &vault.CredentialKeyring{Keyring: keyring}
	credsProvider, err := vault.NewTempCredentialsProvider(config, ckr)
	if err != nil {
		return fmt.Errorf("Error getting temporary credentials: %w", err)
	}

	ecsServer, err := server.NewEcsServer(credsProvider, config, "", input.Port)
	if err != nil {
		return err
	}

	fmt.Println("Starting standalone ECS credential server.")
	fmt.Println("Set the following environment variables to use the ECS credential server:")
	fmt.Println("")
	fmt.Println("      AWS_CONTAINER_AUTHORIZATION_TOKEN=" + ecsServer.AuthToken())
	fmt.Printf("      AWS_CONTAINER_CREDENTIALS_FULL_URI=%s/role-arn/YOUR_ROLE_ARN\n", ecsServer.BaseUrl())
	fmt.Println("")
	fmt.Println("If you wish to use AWS_CONTAINER_CREDENTIALS_RELATIVE_URI=/role-arn/YOUR_ROLE_ARN instead of AWS_CONTAINER_CREDENTIALS_FULL_URI, use a reverse proxy on http://169.254.170.2:80")
	fmt.Println("")

	err = ecsServer.Start()
	if err != nil {
		return err
	}

	return nil
}
