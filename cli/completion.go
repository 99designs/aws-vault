package cli

import (
	"embed"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/alecthomas/kingpin/v2"
)

//go:embed completion-scripts/aws-vault.*
var completionScripts embed.FS

type CompletionCommandInput struct {
	Shell string
}

var completionScriptPrinter io.Writer = os.Stdout

func ConfigureCompletionCommand(app *kingpin.Application) {
	var input CompletionCommandInput

	supportedShells, err := completionSupportedShells()
	if err != nil {
		panic(err)
	}

	cmd := app.Command(
		"completion",
		"Output shell completion script. To be used with `eval $(aws-vault completion SHELL)`.",
	)

	shellArgHelp := fmt.Sprintf("Shell to get completion script for [ %s ]", strings.Join(supportedShells, " "))
	cmd.Arg("shell", shellArgHelp).
		Required().
		Envar("SHELL").
		HintOptions(supportedShells...).
		StringVar(&input.Shell)

	cmd.Action(func(c *kingpin.ParseContext) error {
		shell := path.Base(input.Shell) // strip any path (useful for $SHELL, doesn't hurt for other cases)

		completionScript, err := completionScripts.ReadFile(fmt.Sprintf("completion-scripts/aws-vault.%s", shell))
		if err != nil {
			return fmt.Errorf("unknown shell: %s", input.Shell)
		}

		_, err = fmt.Fprint(completionScriptPrinter, string(completionScript))
		if err != nil {
			return fmt.Errorf("failed to print completion script: %w", err)
		}

		return nil
	})
}

// completionSupportedShells returns a list of shells with available completions.
// The list is generated from the embedded completion scripts.
func completionSupportedShells() ([]string, error) {
	scripts, err := completionScripts.ReadDir("completion-scripts")
	if err != nil {
		return nil, fmt.Errorf("failed to read completion scripts: %w", err)
	}
	var shells []string
	for _, f := range scripts {
		shells = append(shells, strings.Split(path.Ext(f.Name()), ".")[1])
	}
	return shells, nil
}
