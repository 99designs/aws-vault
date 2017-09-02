package vault

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/mitchellh/go-homedir"
	"github.com/vaughan0/go-ini"
)

type Profiles map[string]map[string]string

// SourceProfile returns either the defined source_profile or profileKey if none exists
func (p Profiles) SourceProfile(profileKey string) string {
	if conf, ok := p[profileKey]; ok {
		if source := conf["source_profile"]; source != "" {
			return source
		}
	}
	return profileKey
}

type Config interface {
	Parse() (Profiles, error)
}

type FileConfig struct {
	file string
}

func NewConfigFromEnv() (Config, error) {
	file := os.Getenv("AWS_CONFIG_FILE")
	if file == "" {
		home, err := homedir.Dir()
		if err != nil {
			return nil, err
		}
		file = filepath.Join(home, "/.aws/config")
		if _, err := os.Stat(file); os.IsNotExist(err) {
			file = ""
		}
	}
	return &FileConfig{file: file}, nil
}

func (c *FileConfig) Parse() (Profiles, error) {
	if c.file == "" {
		return nil, nil
	}

	log.Printf("Parsing config file %s", c.file)
	f, err := ini.LoadFile(c.file)
	if err != nil {
		return nil, fmt.Errorf("Error parsing config file %q: %v", c.file, err)
	}

	profiles := Profiles{}

	for sectionName, section := range f {
		profiles[strings.TrimPrefix(sectionName, "profile ")] = section
	}

	return profiles, nil
}

func FormatCredentialError(profileKey string, from Profiles, err error) string {
	source := from.SourceProfile(profileKey)
	sourceDescr := profileKey

	// add custom formatting for source_profile
	if source != profileKey {
		sourceDescr = fmt.Sprintf("%s (source profile for %s)", source, profileKey)
	}

	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
		return fmt.Sprintf(
			"No credentials found for profile %s.\n"+
				"Use 'aws-vault add %s' to set up credentials or 'aws-vault list' to see what credentials exist",
			sourceDescr, source)
	}

	return fmt.Sprintf("Failed to get credentials for %s: %v", sourceDescr, err)
}
