package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/99designs/aws-vault/vault"
	"github.com/99designs/keyring"
	"gopkg.in/alecthomas/kingpin.v2"
)

type LsCommandInput struct {
	Keyring         keyring.Keyring
	OnlyProfiles    bool
	OnlySessions    bool
	OnlyCredentials bool
}

func ConfigureListCommand(app *kingpin.Application) {
	input := LsCommandInput{}

	cmd := app.Command("list", "List profiles, along with their credentials and sessions")
	cmd.Alias("ls")

	cmd.Flag("profiles", "Show only the profile names").
		BoolVar(&input.OnlyProfiles)

	cmd.Flag("sessions", "Show only the session names").
		BoolVar(&input.OnlySessions)

	cmd.Flag("credentials", "Show only the credential names").
		BoolVar(&input.OnlyCredentials)

	cmd.Action(func(c *kingpin.ParseContext) error {
		input.Keyring = keyringImpl
		LsCommand(app, input)
		return nil
	})
}

func contains(aa []string, b string) bool {
	for _, a := range aa {
		if a == b {
			return true
		}
	}
	return false
}

func LsCommand(app *kingpin.Application, input LsCommandInput) {
	krs := vault.NewKeyringSessions(input.Keyring)

	keys, err := input.Keyring.Keys()
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	credentialsNames := []string{}
	sessionNames := []string{}
	for _, c := range keys {
		if vault.IsSessionKey(c) {
			sessionNames = append(sessionNames, c)
		} else {
			credentialsNames = append(credentialsNames, c)
		}
	}

	if input.OnlyCredentials {
		for _, c := range credentialsNames {
			fmt.Printf("%s\n", c)
		}
		return
	}

	if input.OnlyProfiles {
		for _, profileName := range awsConfigFile.ProfileNames() {
			fmt.Printf("%s\n", profileName)
		}
		return
	}

	if input.OnlySessions {
		for _, c := range sessionNames {
			fmt.Printf("%s\n", c)
		}
		return
	}

	sessions, err := krs.Sessions()
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 25, 4, 2, ' ', 0)
	fmt.Fprintln(w, "Profile\tCredentials\tSessions\t")
	fmt.Fprintln(w, "=======\t===========\t========\t")

	// list out known profiles first
	for _, profileName := range awsConfigFile.ProfileNames() {
		fmt.Fprintf(w, "%s\t", profileName)

		config := vault.Config{}
		configLoader.LoadFromProfile(profileName, &config)

		if contains(credentialsNames, config.CredentialsName) {
			fmt.Fprintf(w, "%s\t", config.CredentialsName)
		} else if config.CredentialsName != "" {
			fmt.Fprintf(w, "%s (missing)\t", config.CredentialsName)
		} else {
			fmt.Fprintf(w, "-\t")
		}

		var sessionLabels []string
		for _, sess := range sessions {
			if profileName == sess.ProfileName {
				label := fmt.Sprintf("%d", sess.Expiration.Unix())
				if sess.MfaSerial != "" {
					label += " (mfa)"
				}
				sessionLabels = append(sessionLabels, label)
			}
		}

		if len(sessions) > 0 {
			fmt.Fprintf(w, "%s\t\n", strings.Join(sessionLabels, ", "))
		} else {
			fmt.Fprintf(w, "-\t\n")
		}
	}

	// show credentials that don't have profiles
	for _, credentialName := range credentialsNames {
		_, ok := awsConfigFile.ProfileSection(credentialName)
		if !ok {
			fmt.Fprintf(w, "-\t%s\t-\t\n", credentialName)
		}
	}

	if err = w.Flush(); err != nil {
		app.Fatalf("%v", err)
		return
	}

	if len(keys) == 0 {
		app.Fatalf("No credentials found")
		return
	}
}
