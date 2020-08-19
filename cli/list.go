package cli

import (
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/99designs/aws-vault/v6/vault"
	"github.com/99designs/keyring"
	"github.com/alecthomas/kingpin"
)

type ListCommandInput struct {
	OnlyProfiles    bool
	OnlySessions    bool
	OnlyCredentials bool
}

func ConfigureListCommand(app *kingpin.Application, a *AwsVault) {
	input := ListCommandInput{}

	cmd := app.Command("list", "List profiles, along with their credentials and sessions")
	cmd.Alias("ls")

	cmd.Flag("profiles", "Show only the profile names").
		BoolVar(&input.OnlyProfiles)

	cmd.Flag("sessions", "Show only the session names").
		BoolVar(&input.OnlySessions)

	cmd.Flag("credentials", "Show only the profiles with stored credential").
		BoolVar(&input.OnlyCredentials)

	cmd.Action(func(c *kingpin.ParseContext) (err error) {
		keyring, err := a.Keyring()
		if err != nil {
			return err
		}
		awsConfigFile, err := a.AwsConfigFile()
		if err != nil {
			return err
		}
		err = ListCommand(input, awsConfigFile, keyring)
		app.FatalIfError(err, "list")
		return nil
	})
}

func ListCommand(input ListCommandInput, awsConfigFile *vault.ConfigFile, keyring keyring.Keyring) (err error) {
	ckr := &vault.CredentialKeyring{Keyring: keyring}

	var sessionNames, credentialsNames []string
	var sessions []vault.SessionMetadata

	if !input.OnlyProfiles && !input.OnlySessions {
		credentialsNames, err = ckr.CredentialsKeys()
		if err != nil {
			return err
		}
	}

	if !input.OnlyProfiles && !input.OnlyCredentials {
		sk := &vault.SessionKeyring{Keyring: ckr.Keyring}
		sessions, err = sk.GetAllMetadata()
		if err != nil {
			return err
		}
		for _, sess := range sessions {
			label := fmt.Sprintf("%d", sess.Expiration.Unix())
			if sess.MfaSerial != "" {
				label += " (mfa)"
			}
			sessionNames = append(sessionNames, label)
		}
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
				label := fmt.Sprintf("%s:%s", sess.Type, time.Until(sess.Expiration).Truncate(time.Second))
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
			if vault.IsOIDCTokenKeyringKey(credentialName) {
				oidck := &vault.OIDCTokenKeyring{Keyring: ckr.Keyring}
				token, err := oidck.Get(credentialName)
				if err != nil {
					return err
				}
				timeLeft := time.Duration(*token.ExpiresIn * int64(time.Second))
				fmt.Fprintf(w, "-\t%s\toidc:%s\t\n", credentialName, timeLeft.String())
			} else {
				fmt.Fprintf(w, "-\t%s\t-\t\n", credentialName)
			}
		}
	}

	if err = w.Flush(); err != nil {
		return err
	}

	return nil
}
