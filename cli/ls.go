package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/99designs/aws-vault/v5/vault"
	"gopkg.in/alecthomas/kingpin.v2"
)

type LsCommandInput struct {
	OnlyProfiles    bool
	OnlySessions    bool
	OnlyCredentials bool
}

func ConfigureListCommand(app *kingpin.Application, a *AwsVault) {
	input := LsCommandInput{}

	cmd := app.Command("list", "List profiles, along with their credentials and sessions")
	cmd.Alias("ls")

	cmd.Flag("profiles", "Show only the profile names").
		BoolVar(&input.OnlyProfiles)

	cmd.Flag("sessions", "Show only the session names").
		BoolVar(&input.OnlySessions)

	cmd.Flag("credentials", "Show only the profiles with stored credential").
		BoolVar(&input.OnlyCredentials)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		ckr, err := a.NewCredentialKeyring()
		if err != nil {
			return err
		}
		awsConfigFile, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		err = LsCommand(input, awsConfigFile, ckr)
		app.FatalIfError(err, "list")
		return nil
	})
}

func LsCommand(input LsCommandInput, awsConfigFile *vault.ConfigFile, ckr *vault.CredentialKeyring) error {
	krs := ckr.Sessions()

	credentialsNames, err := ckr.CredentialsKeys()
	if err != nil {
		return err
	}

	sessions, err := krs.Sessions()
	if err != nil {
		return err
	}

	var sessionNames []string
	for _, sess := range sessions {
		label := fmt.Sprintf("%d", sess.Expiration.Unix())
		if sess.MfaSerial != "" {
			label += " (mfa)"
		}
		sessionNames = append(sessionNames, label)

	}

	if input.OnlyCredentials {
		for _, c := range credentialsNames {
			fmt.Printf("%s\n", c)
		}
		return nil
	}

	if input.OnlyProfiles {
		for _, profileName := range awsConfigFile.ProfileNames() {
			fmt.Printf("%s\n", profileName)
		}
		return nil
	}

	if input.OnlySessions {
		for _, c := range sessionNames {
			fmt.Printf("%s\n", c)
		}
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 25, 4, 2, ' ', 0)

	fmt.Fprintln(w, "Profile\tCredentials\tSessions\t")
	fmt.Fprintln(w, "=======\t===========\t========\t")

	// list out known profiles first
	for _, profileName := range awsConfigFile.ProfileNames() {
		fmt.Fprintf(w, "%s\t", profileName)

		hasCred, err := ckr.Has(profileName)
		if err != nil {
			return err
		}

		if hasCred {
			fmt.Fprintf(w, "%s\t", profileName)
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

		if len(sessionLabels) > 0 {
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
		return err
	}

	return nil
}
