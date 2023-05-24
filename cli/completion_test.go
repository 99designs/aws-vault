package cli

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/alecthomas/kingpin/v2"
)

type shellTestDataItem struct {
	shellName        string
	shellPath        string
	completionScript string
}

func TestConfigureCompletionCommand(t *testing.T) {
	app := kingpin.New("test", "")
	ConfigureCompletionCommand(app)

	shellsAndCompletionScripts, err := getShellsAndCompletionScripts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(shellsAndCompletionScripts) == 0 {
		t.Fatal("no shells found")
	}

	invalidShellTestDataItem := shellTestDataItem{
		shellName: "invalid",
		shellPath: "/bin/invalid",
	}
	for _, tt := range shellsAndCompletionScripts {
		if tt.shellName == invalidShellTestDataItem.shellName {
			t.Fatalf("invalidShellTestDataItem.shellName (%s) is actually a valid shell name", invalidShellTestDataItem.shellName)
		}
	}

	// Test shell argument
	t.Run("arg", func(t *testing.T) {
		for _, tt := range shellsAndCompletionScripts {
			t.Run(tt.shellName, func(t *testing.T) {
				var buf bytes.Buffer
				completionScriptPrinter = &buf

				_, err := app.Parse([]string{"completion", tt.shellName})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				got := buf.String()
				if got != tt.completionScript {
					t.Errorf("got %q; want %q", got, tt.completionScript)
				}
			})
		}

		t.Run(invalidShellTestDataItem.shellName, func(t *testing.T) {
			var buf bytes.Buffer
			app.UsageWriter(&buf)

			_, err := app.Parse([]string{"completion", "invalid"})

			if err == nil {
				t.Fatal("expected error, but didn't get one")
			}

			want := fmt.Sprintf("unknown shell: %s", invalidShellTestDataItem.shellName)
			if err.Error() != want {
				t.Errorf("got error(%q); want error(%q)", err.Error(), want)
			}
		})
	})

	// Test $SHELL envar
	t.Run("envar", func(t *testing.T) {
		for _, tt := range shellsAndCompletionScripts {
			t.Run(tt.shellName, func(t *testing.T) {
				var buf bytes.Buffer
				completionScriptPrinter = &buf

				os.Setenv("SHELL", tt.shellPath)

				_, err := app.Parse([]string{"completion"})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}

				got := buf.String()
				if got != tt.completionScript {
					t.Errorf("got %q; want %q", got, tt.completionScript)
				}
			})
		}

		t.Run(invalidShellTestDataItem.shellName, func(t *testing.T) {
			var buf bytes.Buffer
			app.UsageWriter(&buf)

			os.Setenv("SHELL", invalidShellTestDataItem.shellPath)

			_, err := app.Parse([]string{"completion"})
			if err == nil {
				t.Fatal("expected error, but didn't get one")
			}

			want := fmt.Sprintf("unknown shell: %s", invalidShellTestDataItem.shellPath)
			if err.Error() != want {
				t.Errorf("got error(%q); want error(%q)", err.Error(), want)
			}
		})
	})
}

func getShellsAndCompletionScripts() ([]shellTestDataItem, error) {
	shells, err := completionSupportedShells()
	if err != nil {
		return nil, err
	}

	var shellsAndValues []shellTestDataItem
	for _, shell := range shells {
		completionScript, err := completionScripts.ReadFile(fmt.Sprintf("completion-scripts/aws-vault.%s", shell))
		if err != nil {
			return nil, err
		}
		shellsAndValues = append(
			shellsAndValues,
			shellTestDataItem{
				shellName:        shell,
				shellPath:        fmt.Sprintf("/bin/%s", shell),
				completionScript: string(completionScript),
			},
		)
	}
	return shellsAndValues, nil
}
