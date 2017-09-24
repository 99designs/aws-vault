package vault

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws/awserr"
	ini "github.com/go-ini/ini"
	"github.com/mitchellh/go-homedir"
)

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

	return &Config{Path: file}, nil
}

func (c *Config) parseFile() error {
	log.Printf("Parsing config file %s", c.Path)
	f, err := ini.Load(c.Path)
	if err != nil {
		return fmt.Errorf("Error parsing config file %q: %v", c.Path, err)
	}
	c.iniFile = f
	return nil
}

type Profile struct {
	Name            string `ini:"-"`
	MFASerial       string `ini:"mfa_serial"`
	RoleARN         string `ini:"role_arn"`
	Region          string `ini:"region"`
	SourceProfile   string `ini:"source_profile"`
	RoleSessionName string `ini:"role_session_name"`
}

func (p Profile) Hash() ([]byte, error) {
	hasher := md5.New()
	if err := json.NewEncoder(hasher).Encode(p); err != nil {
		return nil, err
	}
	b := hasher.Sum(nil)
	return b, nil
}

// Profile returns the  profile with the matching name. If there isn't any,
// an empty profile with the provided name is returned, along with false.
func (c *Config) Profile(name string) (Profile, bool) {
	profile := Profile{
		Name: name,
	}
	section, err := c.iniFile.GetSection("profile " + name)
	if err != nil {
		return profile, false
	}
	if err = section.MapTo(&profile); err != nil {
		panic(err)
	}
	return profile, true
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
