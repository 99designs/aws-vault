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
	ProfileName         string
	Config              vault.Config
	AuthToken           string
	Port                int
	RoleSessionDuration time.Duration
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
		Default("55777").
		IntVar(&input.Port)
	cmd.Flag("duration", "Duration of the assume-role session. Defaults to 1h").
		Short('d').
		Default("1h").
		DurationVar(&input.RoleSessionDuration)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
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
	vault.UseSession = false

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

	err = server.StartStandaloneEcsRoleCredentialServer(credsProvider, config, input.AuthToken, input.Port, input.RoleSessionDuration)
	if err != nil {
		return fmt.Errorf("Failed to start credential server: %w", err)
	}

	return nil
}
