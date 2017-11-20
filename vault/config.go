package vault

import (
	"crypto/md5"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws/awserr"
	ini "github.com/go-ini/ini"
	"github.com/mitchellh/go-homedir"
)

func init() {
	ini.PrettyFormat = false
}

// Config is an abstraction over what is in ~/.aws/config
type Config struct {
	Path    string
	iniFile *ini.File
}

// ConfigPath returns either $AWS_CONFIG_FILE or ~/.aws/config
func ConfigPath() (string, error) {
	file := os.Getenv("AWS_CONFIG_FILE")
	if file == "" {
		home, err := homedir.Dir()
		if err != nil {
			return "", err
		}
		file = filepath.Join(home, "/.aws/config")
	}
	return file, nil
}

// LoadConfig loads and parses a config. No error is returned if the file doesn't exist
func LoadConfig(path string) (*Config, error) {
	config := &Config{
		Path: path,
	}
	if _, err := os.Stat(path); err == nil {
		if parseErr := config.parseFile(); parseErr != nil {
			return nil, parseErr
		}
	} else {
		log.Printf("Config file %s doesn't exist", path)
	}
	return config, nil
}

// LoadConfigFromEnv finds the config file from the environment
func LoadConfigFromEnv() (*Config, error) {
	file, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	log.Printf("Loading config file %s", file)
	return LoadConfig(file)
}

func (c *Config) parseFile() error {
	log.Printf("Parsing config file %s", c.Path)
	f, err := ini.LoadSources(ini.LoadOptions{
		AllowNestedValues: true,
	}, c.Path)
	if err != nil {
		return fmt.Errorf("Error parsing config file %q: %v", c.Path, err)
	}
	c.iniFile = f
	return nil
}

type Profile struct {
	Name            string `ini:"-"`
	MFASerial       string `ini:"mfa_serial,omitempty"`
	RoleARN         string `ini:"role_arn,omitempty"`
	Region          string `ini:"region,omitempty"`
	SourceProfile   string `ini:"source_profile,omitempty"`
	RoleSessionName string `ini:"role_session_name,omitempty"`
}

func (p Profile) Hash() ([]byte, error) {
	hasher := md5.New()
	if err := json.NewEncoder(hasher).Encode(p); err != nil {
		return nil, err
	}
	b := hasher.Sum(nil)
	return b, nil
}

func readProfileFromIni(f *ini.File, sectionName string, profile *Profile) error {
	if f == nil {
		return errors.New("No ini file available")
	}
	section, err := f.GetSection(sectionName)
	if err != nil {
		return err
	}
	if err = section.MapTo(&profile); err != nil {
		return err
	}
	return nil
}

// Profiles returns all the profiles in the config
func (c *Config) Profiles() []Profile {
	var result []Profile

	if c.iniFile == nil {
		return result
	}

	for _, section := range c.iniFile.SectionStrings() {
		if section != "DEFAULT" {
			profile, _ := c.Profile(strings.TrimPrefix(section, "profile "))
			result = append(result, profile)
		}
	}

	return result
}

// Profile returns the  profile with the matching name. If there isn't any,
// an empty profile with the provided name is returned, along with false.
func (c *Config) Profile(name string) (Profile, bool) {
	profile := Profile{
		Name: name,
	}
	if c.iniFile == nil {
		return profile, false
	}
	// default profile name has a slightly different section format
	sectionName := "profile " + name
	if name == "default" {
		sectionName = "default"
	}
	section, err := c.iniFile.GetSection(sectionName)
	if err != nil {
		return profile, false
	}
	if err = section.MapTo(&profile); err != nil {
		panic(err)
	}
	return profile, true
}

// Add the profile to the configuration file
func (c *Config) Add(profile Profile) error {
	if c.iniFile == nil {
		return errors.New("No iniFile to add to")
	}
	// default profile name has a slightly different section format
	sectionName := "profile " + profile.Name
	if profile.Name == "default" {
		sectionName = "default"
	}
	section, err := c.iniFile.NewSection(sectionName)
	if err != nil {
		return fmt.Errorf("Error creating section %q: %v", profile.Name, err)
	}
	if err = section.ReflectFrom(&profile); err != nil {
		return fmt.Errorf("Error mapping profile to ini file: %v", err)
	}
	return c.iniFile.SaveTo(c.Path)
}

// SourceProfile returns the source profile of the given profile. If there isn't any,
// the named profile, a new profile is returned. False is only returned if no profile by the name exists.
func (c *Config) SourceProfile(name string) (Profile, bool) {
	profile, ok := c.Profile(name)
	if profile.SourceProfile != "" {
		return c.Profile(profile.SourceProfile)
	}
	return profile, ok
}

// FormatCredentialError formats errors with some user friendly context
func (c *Config) FormatCredentialError(err error, profileName string) string {
	source, _ := c.SourceProfile(profileName)
	sourceDescr := profileName

	// add custom formatting for source_profile
	if source.Name != profileName {
		sourceDescr = fmt.Sprintf("%s (source profile for %s)", source.Name, profileName)
	}

	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
		return fmt.Sprintf(
			"No credentials found for profile %s.\n"+
				"Use 'aws-vault add %s' to set up credentials or 'aws-vault list' to see what credentials exist",
			sourceDescr, source.Name)
	}

	return fmt.Sprintf("Failed to get credentials for %s: %v", sourceDescr, err)
}
