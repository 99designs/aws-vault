package vault_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/99designs/aws-vault/vault"
	"github.com/google/go-cmp/cmp"
)

// see http://docs.aws.amazon.com/cli/latest/userguide/cli-multiple-profiles.html
var exampleConfig = []byte(`# an example profile file
[default]
region=us-west-2
output=json

[profile user2]
REGION=us-east-1
output=text

[profile withsource]
source_profile=user2
region=us-east-1

[profile withMFA]
source_profile=user2
role_arn=arn:aws:iam::4451234513441615400570:role/aws_admin
mfa_Serial=arn:aws:iam::1234513441:mfa/blah
region=us-east-1
duration_seconds=1200

[profile testparentprofile1]
region=us-east-1

[profile testparentprofile2]
parent_profile=testparentprofile1
`)

var nestedConfig = []byte(`[default]

[profile testing]
aws_access_key_id=foo
aws_secret_access_key=bar
region=us-west-2
s3=
  max_concurrent_requests=10
  max_queue_size=1000
`)

var defaultsOnlyConfigWithHeader = []byte(`[default]
region=us-west-2
output=json

`)

var defaultsOnlyConfigWithoutHeader = []byte(`region=us-west-2
output=json

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

func TestConfigCaseInsensitivity(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	def, ok := cfg.ProfileSection("withmfa")
	if !ok {
		t.Fatalf("Expected to match profile withMFA")
	}

	expectedMfaSerial := "arn:aws:iam::1234513441:mfa/blah"
	if def.MfaSerial != expectedMfaSerial {
		t.Fatalf("Expected %s, got %s", expectedMfaSerial, def.MfaSerial)
	}
}

func TestConfigParsingProfiles(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	var testCases = []struct {
		expected vault.ProfileSection
		ok       bool
	}{
		{vault.ProfileSection{Name: "user2", Region: "us-east-1"}, true},
		{vault.ProfileSection{Name: "withsource", SourceProfile: "user2", Region: "us-east-1"}, true},
		{vault.ProfileSection{Name: "withmfa", MfaSerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", DurationSeconds: 1200, SourceProfile: "user2"}, true},
		{vault.ProfileSection{Name: "nopenotthere"}, false},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("profile_%s", tc.expected.Name), func(t *testing.T) {
			actual, ok := cfg.ProfileSection(tc.expected.Name)
			if ok != tc.ok {
				t.Fatalf("Expected second param to be %v, got %v", tc.ok, ok)
			}
			if diff := cmp.Diff(tc.expected, actual); diff != "" {
				t.Errorf("ProfileSection() mismatch (-expected +actual):\n%s", diff)
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

	def, ok := cfg.ProfileSection("default")
	if !ok {
		t.Fatalf("Expected to find default profile")
	}

	expected := vault.ProfileSection{
		Name:   "default",
		Region: "us-west-2",
	}

	if !reflect.DeepEqual(def, expected) {
		t.Fatalf("Expected %+v, got %+v", expected, def)
	}
}

func TestCredentialsNameFromConfig(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	configLoader := &vault.ConfigLoader{File: configFile}
	config := vault.Config{}
	err = configLoader.LoadFromProfile("withmfa", &config)
	if err != nil {
		t.Fatalf("Should have found a profile")
	}

	if config.CredentialsName != "user2" {
		t.Fatalf("Expected CredentialsName name %q, got %q", "user2", config.CredentialsName)
	}
}

func TestProfilesFromConfig(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	expected := []vault.ProfileSection{
		vault.ProfileSection{Name: "default", Region: "us-west-2"},
		vault.ProfileSection{Name: "user2", Region: "us-east-1"},
		vault.ProfileSection{Name: "withsource", Region: "us-east-1", SourceProfile: "user2"},
		vault.ProfileSection{Name: "withmfa", MfaSerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", DurationSeconds: 1200, SourceProfile: "user2"},
		vault.ProfileSection{Name: "testparentprofile1", Region: "us-east-1"},
		vault.ProfileSection{Name: "testparentprofile2", ParentProfile: "testparentprofile1"},
	}
	actual := cfg.ProfileSections()

	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("ProfileSections() mismatch (-expected +actual):\n%s", diff)
	}
}

func TestAddProfileToExistingConfig(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Add(vault.ProfileSection{
		Name:          "llamas",
		MfaSerial:     "testserial",
		Region:        "us-east-1",
		SourceProfile: "default",
	})
	if err != nil {
		t.Fatalf("Error adding profile: %#v", err)
	}

	expected := []vault.ProfileSection{
		vault.ProfileSection{Name: "default", Region: "us-west-2"},
		vault.ProfileSection{Name: "user2", Region: "us-east-1"},
		vault.ProfileSection{Name: "withsource", Region: "us-east-1", SourceProfile: "user2"},
		vault.ProfileSection{Name: "withmfa", MfaSerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", DurationSeconds: 1200, SourceProfile: "user2"},
		vault.ProfileSection{Name: "testparentprofile1", Region: "us-east-1"},
		vault.ProfileSection{Name: "testparentprofile2", ParentProfile: "testparentprofile1"},
		vault.ProfileSection{Name: "llamas", MfaSerial: "testserial", Region: "us-east-1", SourceProfile: "default"},
	}
	actual := cfg.ProfileSections()

	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("ProfileSections() mismatch (-expected +actual):\n%s", diff)
	}
}

func TestAddProfileToExistingNestedConfig(t *testing.T) {
	f := newConfigFile(t, nestedConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Add(vault.ProfileSection{
		Name:      "llamas",
		MfaSerial: "testserial",
		Region:    "us-east-1",
	})
	if err != nil {
		t.Fatalf("Error adding profile: %#v", err)
	}

	expected := append(nestedConfig, []byte(
		"\n[profile llamas]\nmfa_serial=testserial\nregion=us-east-1\n\n",
	)...)

	b, _ := ioutil.ReadFile(f)

	if !bytes.Equal(expected, b) {
		t.Fatalf("Expected:\n%q\nGot:\n%q", expected, b)
	}

}

func TestParentProfile(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	configLoader := &vault.ConfigLoader{File: configFile}
	config := vault.Config{}
	err = configLoader.LoadFromProfile("testparentprofile2", &config)
	if err != nil {
		t.Fatalf("Should have found a profile")
	}

	if config.CredentialsName != "testparentprofile1" {
		t.Fatalf("Expected CredentialsName name %q, got %q", "testparentprofile1", config.CredentialsName)
	}
	if config.Region != "us-east-1" {
		t.Fatalf("Expected CredentialsName name %q, got %q", "us-east-1", config.CredentialsName)
	}
}

func TestProfileIsEmpty(t *testing.T) {
	p := vault.ProfileSection{Name: "foo"}
	if !p.IsEmpty() {
		t.Errorf("Expected p to be empty")
	}
}

func TestIniWithHeaderSavesWithHeader(t *testing.T) {
	f := newConfigFile(t, defaultsOnlyConfigWithHeader)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	err = cfg.Save()
	if err != nil {
		t.Fatal(err)
	}

	expected := defaultsOnlyConfigWithHeader

	b, _ := ioutil.ReadFile(f)

	if !bytes.Equal(expected, b) {
		t.Fatalf("Expected:\n%q\nGot:\n%q", expected, b)
	}

}

func TestIniWithoutHeaderSavesWithHeader(t *testing.T) {
    f := newConfigFile(t, defaultsOnlyConfigWithoutHeader)
    defer os.Remove(f)

    cfg, err := vault.LoadConfig(f)
    if err != nil {
        t.Fatal(err)
    }

    err = cfg.Save()
    if err != nil {
        t.Fatal(err)
    }

    expected := defaultsOnlyConfigWithHeader

    b, _ := ioutil.ReadFile(f)

    if !bytes.Equal(expected, b) {
        t.Fatalf("Expected:\n%q\nGot:\n%q", expected, b)
    }

}
