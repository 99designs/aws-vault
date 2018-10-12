package vault_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/99designs/aws-vault/vault"
)

// see http://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html
var exampleConfig = []byte(`# an example profile file
[default]
region=us-west-2
output=json

[profile user2]
region=us-east-1
output=text

[profile withsource]
source_profile=user2
region=us-east-1

[profile withmfa]
source_profile=user2
role_arn=arn:aws:iam::4451234513441615400570:role/aws_admin
mfa_serial=arn:aws:iam::1234513441:mfa/blah
region=us-east-1
`)

var nestedConfig = []byte(`[profile testing]
aws_access_key_id=foo
aws_secret_access_key=bar
region=us-west-2
s3=
  max_concurrent_requests=10
  max_queue_size=1000
`)

func newConfigFile(t *testing.T, b []byte) string {
	f, err := ioutil.TempFile("", "aws-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(f.Name(), b, 0600); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestConfigParsingProfiles(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	var testCases = []struct {
		expected vault.Profile
		ok       bool
	}{
		{vault.Profile{Name: "user2", Region: "us-east-1"}, true},
		{vault.Profile{Name: "withsource", SourceProfile: "user2", Region: "us-east-1"}, true},
		{vault.Profile{
			Name:          "withmfa",
			SourceProfile: "user2",
			Region:        "us-east-1",
			RoleARN:       "arn:aws:iam::4451234513441615400570:role/aws_admin",
			MFASerial:     "arn:aws:iam::1234513441:mfa/blah",
		}, true},
		{vault.Profile{Name: "nopenotthere"}, false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("profile_%s", tc.expected.Name), func(t *testing.T) {
			actual, ok := cfg.Profile(tc.expected.Name)
			if ok != tc.ok {
				t.Fatalf("Expected second param to be %v, got %v", tc.ok, ok)
			}
			if !reflect.DeepEqual(actual, tc.expected) {
				t.Fatalf("Expected %#v, got %#v", tc.expected, actual)
			}
		})
	}
}

func TestConfigParsingDefault(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	def, ok := cfg.Profile("default")
	if !ok {
		t.Fatalf("Expected to find default profile")
	}

	expected := vault.Profile{
		Name:   "default",
		Region: "us-west-2",
	}

	if !reflect.DeepEqual(def, expected) {
		t.Fatalf("Expected %+v, got %+v", expected, def)
	}
}

func TestSourceProfileFromConfig(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	source, ok := cfg.SourceProfile("withmfa")
	if !ok {
		t.Fatalf("Should have found a source")
	}

	if source.Name != "user2" {
		t.Fatalf("Expected source name %q, got %q", "user2", source.Name)
	}
}

func TestProfilesFromConfig(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	profiles := cfg.Profiles()
	expected := []vault.Profile{
		vault.Profile{Name: "default", Region: "us-west-2"},
		vault.Profile{Name: "user2", Region: "us-east-1"},
		vault.Profile{Name: "withsource", Region: "us-east-1", SourceProfile: "user2"},
		vault.Profile{Name: "withmfa", MFASerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", SourceProfile: "user2"},
	}

	if !reflect.DeepEqual(expected, profiles) {
		t.Fatalf("Expected %+v, got %+v", expected, profiles)
	}
}

func TestAddProfileToExistingConfig(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Add(vault.Profile{
		Name:          "llamas",
		MFASerial:     "testserial",
		Region:        "us-east-1",
		SourceProfile: "default",
	})
	if err != nil {
		t.Fatalf("Error adding profile: %#v", err)
	}

	profiles := cfg.Profiles()
	expected := []vault.Profile{
		vault.Profile{Name: "default", Region: "us-west-2"},
		vault.Profile{Name: "user2", Region: "us-east-1"},
		vault.Profile{Name: "withsource", Region: "us-east-1", SourceProfile: "user2"},
		vault.Profile{Name: "withmfa", MFASerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", SourceProfile: "user2"},
		vault.Profile{Name: "llamas", MFASerial: "testserial", Region: "us-east-1", SourceProfile: "default"},
	}

	if !reflect.DeepEqual(expected, profiles) {
		t.Fatalf("Expected:\n%+v\nGot:\n%+v", expected, profiles)
	}
}

func TestAddProfileToExistingNestedConfig(t *testing.T) {
	f := newConfigFile(t, nestedConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Add(vault.Profile{
		Name:      "llamas",
		MFASerial: "testserial",
		Region:    "us-east-1",
	})
	if err != nil {
		t.Fatalf("Error adding profile: %#v", err)
	}

	expected := append(nestedConfig, []byte(
		"\n[profile llamas]\nmfa_serial=testserial\nregion=us-east-1\n\n",
	)...)

	b, _ := ioutil.ReadFile(f)
	actual := normaliseLineEndings(b)

	if !bytes.Equal(expected, actual) {
		t.Fatalf("Expected:\n%q\nGot:\n%q", expected, actual)
	}

}

func normaliseLineEndings(b []byte) []byte {
	return bytes.Replace(b, []byte("\r\n"), []byte("\n"), -1)
}
