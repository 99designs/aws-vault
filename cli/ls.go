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

	cmd.Flag("profile", "Show only the profile names").
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

func containsProfile(profile string, accounts []string) bool {
	for _, account := range accounts {
		if !vault.IsSessionKey(account) && account == profile {
			return true
		}
	}
	return false
}

func LsCommand(app *kingpin.Application, input LsCommandInput) {
	krs, err := vault.NewKeyringSessions(input.Keyring, awsConfig)
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	accounts, err := input.Keyring.Keys()
	if err != nil {
		app.Fatalf(err.Error())
		return
	}

	if input.OnlyCredentials {
		for _, account := range accounts {
			if !vault.IsSessionKey(account) {
				fmt.Printf("%s\n", account)
			}
		}
		return
	}

	if input.OnlyProfiles {
		for _, profile := range awsConfig.Profiles() {
			fmt.Printf("%s\n", profile.Name)
		}
		return
	}

	if input.OnlySessions {
		for _, account := range accounts {
			if vault.IsSessionKey(account) {
				fmt.Printf("%s\n", account)
			}
		}
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 25, 4, 2, ' ', 0)
	fmt.Fprintln(w, "Profile\tCredentials\tSessions\t")
	fmt.Fprintln(w, "=======\t===========\t========\t")

	// list out known profiles first
	for _, profile := range awsConfig.Profiles() {
		fmt.Fprintf(w, "%s\t", profile.Name)

		source, _ := awsConfig.SourceProfile(profile.Name)
		if containsProfile(source.Name, accounts) {
			fmt.Fprintf(w, "%s\t", source.Name)
		} else {
			fmt.Fprintf(w, "-\t")
		}

		sessions, err := krs.Sessions(source.Name)
		if err != nil {
			app.Fatalf(err.Error())
			return
		} else if len(sessions) > 0 {
			var sessionIDs []string
			for _, sess := range sessions {
				sessionIDs = append(sessionIDs, sess.SessionID)
			}
			fmt.Fprintf(w, "%s\t\n", strings.Join(sessionIDs, ", "))
		} else {
			fmt.Fprintf(w, "-\t\n")
		}
	}

	// show credentials that don't have profiles
	for _, account := range accounts {
		if !vault.IsSessionKey(account) {
			if _, ok := awsConfig.Profile(account); !ok {
				fmt.Fprintf(w, "-\t%s\t-\t\n", account)
			}
		}
	}

	if err = w.Flush(); err != nil {
		app.Fatalf("%v", err)
		return
	}

	if len(accounts) == 0 {
		app.Fatalf("No credentials found")
		return
	}
}
