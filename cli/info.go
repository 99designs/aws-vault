package cli

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/99designs/aws-vault/v6/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type InfoCommandInput struct {
	ProfileName string
	Config      vault.Config

	CredentialAge bool
	RotatedTime   bool

	ValuesOnly bool
	UseSeconds bool
}

func ConfigureInfoCommand(app *kingpin.Application, a *AwsVault) {
	input := InfoCommandInput{}

	cmd := app.Command("info", "Reports information about the given profile")

	// Sanest way to indicate to the user that if they don't explicitly ask for
	// one field (eg, age) then they see all of them?

	// For both age and rotated time, we're using modification time as a proxy;
	// as long as aws-vault created the credentials, it will be accurate, but
	// if older credentials were fed in, it won't be.  Changing that will
	// require validation of new credentials at addition time.
	// Fortunately, per <https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_getsessiontoken.html>,
	// "No permissions are required for a user to get a session token."
	// so there are no problems with IAM policies to worry about, it's simply a
	// matter of writing the code to support it and figuring out what the
	// default should be.

	cmd.Flag("age", "Report the age of the credentials").
		Short('a').
		BoolVar(&input.CredentialAge)
	cmd.Flag("rotated-time", "Report when the credentials were last modified (rotated)").
		Short('r').
		BoolVar(&input.RotatedTime)

	// Add other display fields here

	cmd.Flag("values-only", "Skip keys, just show values").
		Short('V').
		BoolVar(&input.ValuesOnly)

	cmd.Flag("seconds", "Report timestamps in Unix epoch seconds, durations in seconds").
		Short('s').
		BoolVar(&input.UseSeconds)

	cmd.Arg("profile", "Name of the profile").
		Required().
		HintAction(a.MustGetProfileNames).
		StringVar(&input.ProfileName)

	cmd.Action(func(c *kingpin.ParseContext) error {
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		configLoader, err := a.ConfigLoader()
		if err != nil {
			return err
		}

		err = InfoCommand(input, configLoader, keyring)
		app.FatalIfError(err, "info")
		return nil
	})
}

func InfoCommand(input InfoCommandInput, configLoader *vault.ConfigLoader, keyring keyring.Keyring) error {
	configLoader.BaseConfig = input.Config
	configLoader.ActiveProfile = input.ProfileName
	config, err := configLoader.LoadFromProfile(input.ProfileName)
	if err != nil {
		return err
	}

	originalProfileName := config.ProfileName

	// At this time, we're only reporting age of credentials, so we only care
	// about profiles which let us identify stored credentials, but not
	// necessarily directly.  We'll chase to a source profile.
	for config.SourceProfile != nil {
		config = config.SourceProfile
	}

	meta, err := keyring.GetMetadata(config.ProfileName)
	if err != nil {
		if config.ProfileName == originalProfileName {
			return fmt.Errorf("failed to get credentials for %q: %w", config.ProfileName, err)
		}
		return fmt.Errorf("failed to get credentials for %q via source %q: %w", config.ProfileName, originalProfileName, err)
	}

	log.Printf("meta: %#+v\n", meta)

	// As more display fields are added, || them into seenSomething
	seenSomething := input.CredentialAge || input.RotatedTime
	if !seenSomething {
		// As more display fields are added, set them all here
		input.CredentialAge = true
		input.RotatedTime = true
	}

	if input.RotatedTime {
		// Using the modification time is a bit wrong if the credentials
		// existed before being added to Vault, but it's the best we have
		// barring recording the time when adding the keys into Vault, and at
		// present the add logic doesn't validate in AWS.
		showTimeField("rotated-time", meta.ModificationTime, input)
	}

	if input.CredentialAge {
		showDurationField("age", time.Now().Sub(meta.ModificationTime), input)
	}

	return nil
}

func showStringField(label, value string, input InfoCommandInput) {
	if input.ValuesOnly {
		fmt.Println(value)
	} else {
		fmt.Printf("%s: %s\n", label, value)
	}
}

func showTimeField(label string, ts time.Time, input InfoCommandInput) {
	var displayTime string
	if input.UseSeconds {
		displayTime = strconv.FormatInt(ts.Unix(), 10)
	} else {
		displayTime = ts.In(time.UTC).Format(time.RFC3339)
	}
	showStringField(label, displayTime, input)
}

func showDurationField(label string, dur time.Duration, input InfoCommandInput) {
	var displayDuration string
	if input.UseSeconds {
		displayDuration = strconv.FormatFloat(dur.Seconds(), 'f', 0, 64)
	} else {
		if dur < 2*time.Minute {
			displayDuration = strconv.FormatFloat(dur.Seconds(), 'f', 0, 64) + " seconds"
		} else if dur < 2*time.Hour {
			displayDuration = strconv.FormatFloat(dur.Minutes(), 'f', 0, 64) + " minutes"
		} else if dur < 48*time.Hour {
			displayDuration = strconv.FormatFloat(dur.Hours(), 'f', 0, 64) + " hours"
		} else {
			displayDuration = strconv.FormatFloat(dur.Hours()/24, 'f', 0, 64) + " days"
		}
	}
	showStringField(label, displayDuration, input)
}
