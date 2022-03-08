package vault_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/99designs/aws-vault/v6/vault"
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
Role_Arn=arn:aws:iam::4451234513441615400570:role/aws_admin
mfa_Serial=arn:aws:iam::1234513441:mfa/blah
Region=us-east-1
duration_seconds=1200
sts_regional_endpoints=legacy

[profile testincludeprofile1]
region=us-east-1

[profile testincludeprofile2]
include_profile=testincludeprofile1
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

func newConfigFile(t *testing.T, b []byte) string {
	t.Helper()
	f, err := ioutil.TempFile("", "aws-config")
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(f.Name(), b, 0600); err != nil {
		t.Fatal(err)
	}
	return f.Name()
}

func TestProfileNameCaseSensitivity(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	def, ok := cfg.ProfileSection("withMFA")
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
		{vault.ProfileSection{Name: "withMFA", MfaSerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", DurationSeconds: 1200, SourceProfile: "user2", STSRegionalEndpoints: "legacy"}, true},
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

func TestProfilesFromConfig(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	expected := []vault.ProfileSection{
		{Name: "default", Region: "us-west-2"},
		{Name: "user2", Region: "us-east-1"},
		{Name: "withsource", Region: "us-east-1", SourceProfile: "user2"},
		{Name: "withMFA", MfaSerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", DurationSeconds: 1200, SourceProfile: "user2", STSRegionalEndpoints: "legacy"},
		{Name: "testincludeprofile1", Region: "us-east-1"},
		{Name: "testincludeprofile2", IncludeProfile: "testincludeprofile1"},
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
		{Name: "default", Region: "us-west-2"},
		{Name: "user2", Region: "us-east-1"},
		{Name: "withsource", Region: "us-east-1", SourceProfile: "user2"},
		{Name: "withMFA", MfaSerial: "arn:aws:iam::1234513441:mfa/blah", RoleARN: "arn:aws:iam::4451234513441615400570:role/aws_admin", Region: "us-east-1", DurationSeconds: 1200, SourceProfile: "user2", STSRegionalEndpoints: "legacy"},
		{Name: "testincludeprofile1", Region: "us-east-1"},
		{Name: "testincludeprofile2", IncludeProfile: "testincludeprofile1"},
		{Name: "llamas", MfaSerial: "testserial", Region: "us-east-1", SourceProfile: "default"},
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

func TestIncludeProfile(t *testing.T) {
	f := newConfigFile(t, exampleConfig)
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	configLoader := &vault.ConfigLoader{File: configFile}
	config, err := configLoader.LoadFromProfile("testincludeprofile2")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	if config.Region != "us-east-1" {
		t.Fatalf("Expected region %q, got %q", "us-east-1", config.Region)
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

func TestIniWithDEFAULTHeader(t *testing.T) {
	f := newConfigFile(t, []byte(`[DEFAULT]
region=us-east-1
[default]
region=us-west-2
`))
	defer os.Remove(f)

	cfg, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	expected := []vault.ProfileSection{
		{Name: "default", Region: "us-west-2"},
	}
	actual := cfg.ProfileSections()

	if diff := cmp.Diff(expected, actual); diff != "" {
		t.Errorf("ProfileSections() mismatch (-expected +actual):\n%s", diff)
	}
}

func TestLoadedProfileDoesntReferToItself(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile foo]
source_profile=foo
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	def, ok := configFile.ProfileSection("foo")
	if !ok {
		t.Fatalf("Couldn't load profile foo")
	}

	expectedSourceProfile := "foo"
	if def.SourceProfile != expectedSourceProfile {
		t.Fatalf("Expected '%s', got '%s'", expectedSourceProfile, def.SourceProfile)
	}

	configLoader := &vault.ConfigLoader{File: configFile}
	config, err := configLoader.LoadFromProfile("foo")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	expectedSourceProfileName := ""
	if config.SourceProfileName != expectedSourceProfileName {
		t.Fatalf("Expected '%s', got '%s'", expectedSourceProfileName, config.SourceProfileName)
	}
}

func TestSourceProfileCanReferToParent(t *testing.T) {
	f := newConfigFile(t, []byte(`
[profile root]

[profile foo]
include_profile=root
source_profile=root
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}

	def, ok := configFile.ProfileSection("foo")
	if !ok {
		t.Fatalf("Couldn't load profile foo")
	}

	expectedSourceProfile := "root"
	if def.SourceProfile != expectedSourceProfile {
		t.Fatalf("Expected '%s', got '%s'", expectedSourceProfile, def.SourceProfile)
	}

	configLoader := &vault.ConfigLoader{File: configFile}
	config, err := configLoader.LoadFromProfile("foo")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	expectedSourceProfileName := "root"
	if config.SourceProfileName != expectedSourceProfileName {
		t.Fatalf("Expected '%s', got '%s'", expectedSourceProfileName, config.SourceProfileName)
	}
}

func TestSetSessionTags(t *testing.T) {
	var testCases = []struct {
		stringValue string
		expected    map[string]string
		ok          bool
	}{
		{"tag1=value1", map[string]string{"tag1": "value1"}, true},
		{
			"tag2=value2,tag3=value3,tag4=value4",
			map[string]string{"tag2": "value2", "tag3": "value3", "tag4": "value4"},
			true,
		},
		{" tagA = valueA ,  tagB  =  valueB  ,  tagC   =   valueC  ",
			map[string]string{"tagA": "valueA", "tagB": "valueB", "tagC": "valueC"},
			true,
		},
		{"", nil, false},
		{"tag1=value1,", nil, false},
		{"tagA=valueA,tagB", nil, false},
		{"tagOne,tagTwo=valueTwo", nil, false},
		{"tagI=valueI,tagII,tagIII=valueIII", nil, false},
	}

	for _, tc := range testCases {
		config := vault.Config{}
		err := config.SetSessionTags(tc.stringValue)
		if tc.ok {
			if err != nil {
				t.Fatalf("Unsexpected parsing error: %s", err)
			}
			if !reflect.DeepEqual(tc.expected, config.SessionTags) {
				t.Fatalf("Expected SessionTags: %+v, got %+v", tc.expected, config.SessionTags)
			}
		} else {
			if err == nil {
				t.Fatalf("Expected an error parsing %#v, but got none", tc.stringValue)
			}
		}
	}
}

func TestSetTransitiveSessionTags(t *testing.T) {
	var testCases = []struct {
		stringValue string
		expected    []string
	}{
		{"tag1", []string{"tag1"}},
		{"tag2,tag3,tag4", []string{"tag2", "tag3", "tag4"}},
		{" tagA ,  tagB  ,   tagC   ", []string{"tagA", "tagB", "tagC"}},
		{"tag1,", []string{"tag1"}},
		{",tagA", []string{"tagA"}},
		{"", nil},
		{",", nil},
	}

	for _, tc := range testCases {
		config := vault.Config{}
		config.SetTransitiveSessionTags(tc.stringValue)
		if !reflect.DeepEqual(tc.expected, config.TransitiveSessionTags) {
			t.Fatalf("Expected TransitiveSessionTags: %+v, got %+v", tc.expected, config.TransitiveSessionTags)
		}
	}
}

func TestSessionTaggingFromIni(t *testing.T) {
	os.Unsetenv("AWS_SESSION_TAGS")
	os.Unsetenv("AWS_TRANSITIVE_TAGS")
	f := newConfigFile(t, []byte(`
[profile tagged]
session_tags = tag1 = value1 , tag2=value2 ,tag3=value3
transitive_session_tags = tagOne ,tagTwo,tagThree
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "tagged"}
	config, err := configLoader.LoadFromProfile("tagged")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	expectedSessionTags := map[string]string{
		"tag1": "value1",
		"tag2": "value2",
		"tag3": "value3",
	}
	if !reflect.DeepEqual(expectedSessionTags, config.SessionTags) {
		t.Fatalf("Expected session_tags: %+v, got %+v", expectedSessionTags, config.SessionTags)
	}

	expectedTransitiveSessionTags := []string{"tagOne", "tagTwo", "tagThree"}
	if !reflect.DeepEqual(expectedTransitiveSessionTags, config.TransitiveSessionTags) {
		t.Fatalf("Expected transitive_session_tags: %+v, got %+v", expectedTransitiveSessionTags, config.TransitiveSessionTags)
	}
}

func TestSessionTaggingFromEnvironment(t *testing.T) {
	os.Setenv("AWS_SESSION_TAGS", " tagA = val1 , tagB=val2 ,tagC=val3")
	os.Setenv("AWS_TRANSITIVE_TAGS", " tagD ,tagE")
	defer os.Unsetenv("AWS_SESSION_TAGS")
	defer os.Unsetenv("AWS_TRANSITIVE_TAGS")

	f := newConfigFile(t, []byte(`
[profile tagged]
session_tags = tag1 = value1 , tag2=value2 ,tag3=value3
transitive_session_tags = tagOne ,tagTwo,tagThree
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "tagged"}
	config, err := configLoader.LoadFromProfile("tagged")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}
	expectedSessionTags := map[string]string{
		"tagA": "val1",
		"tagB": "val2",
		"tagC": "val3",
	}
	if !reflect.DeepEqual(expectedSessionTags, config.SessionTags) {
		t.Fatalf("Expected session_tags: %+v, got %+v", expectedSessionTags, config.SessionTags)
	}

	expectedTransitiveSessionTags := []string{"tagD", "tagE"}
	if !reflect.DeepEqual(expectedTransitiveSessionTags, config.TransitiveSessionTags) {
		t.Fatalf("Expected transitive_session_tags: %+v, got %+v", expectedTransitiveSessionTags, config.TransitiveSessionTags)
	}
}

func TestSessionTaggingFromEnvironmentChainedRoles(t *testing.T) {
	os.Setenv("AWS_SESSION_TAGS", "tagI=valI")
	os.Setenv("AWS_TRANSITIVE_TAGS", " tagII")
	defer os.Unsetenv("AWS_SESSION_TAGS")
	defer os.Unsetenv("AWS_TRANSITIVE_TAGS")

	f := newConfigFile(t, []byte(`
[profile base]

[profile interim]
session_tags=tag1=value1
transitive_session_tags=tag2
source_profile = base

[profile target]
session_tags=tagA=valueA
transitive_session_tags=tagB
source_profile = interim
`))
	defer os.Remove(f)

	configFile, err := vault.LoadConfig(f)
	if err != nil {
		t.Fatal(err)
	}
	configLoader := &vault.ConfigLoader{File: configFile, ActiveProfile: "target"}
	config, err := configLoader.LoadFromProfile("target")
	if err != nil {
		t.Fatalf("Should have found a profile: %v", err)
	}

	// Testing target profile, should have values populated from environment variables
	expectedSessionTags := map[string]string{"tagI": "valI"}
	if !reflect.DeepEqual(expectedSessionTags, config.SessionTags) {
		t.Fatalf("Expected session_tags: %+v, got %+v", expectedSessionTags, config.SessionTags)
	}

	expectedTransitiveSessionTags := []string{"tagII"}
	if !reflect.DeepEqual(expectedTransitiveSessionTags, config.TransitiveSessionTags) {
		t.Fatalf("Expected transitive_session_tags: %+v, got %+v", expectedTransitiveSessionTags, config.TransitiveSessionTags)
	}

	// Testing interim profile, parameters should come from the config, not environment
	interimConfig := config.SourceProfile
	expectedSessionTags = map[string]string{"tag1": "value1"}
	if !reflect.DeepEqual(expectedSessionTags, interimConfig.SessionTags) {
		t.Fatalf("Expected session_tags: %+v, got %+v", expectedSessionTags, interimConfig.SessionTags)
	}

	expectedTransitiveSessionTags = []string{"tag2"}
	if !reflect.DeepEqual(expectedTransitiveSessionTags, interimConfig.TransitiveSessionTags) {
		t.Fatalf("Expected transitive_session_tags: %+v, got %+v", expectedTransitiveSessionTags, interimConfig.TransitiveSessionTags)
	}

	// Testing base profile, should have empty parameters
	baseConfig := interimConfig.SourceProfile
	if len(baseConfig.SessionTags) > 0 {
		t.Fatalf("Expected session_tags to be empty, got %+v", baseConfig.SessionTags)
	}

	if len(baseConfig.TransitiveSessionTags) > 0 {
		t.Fatalf("Expected transitive_session_tags to be empty, got %+v", baseConfig.TransitiveSessionTags)
	}
}
