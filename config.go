package main

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

type profiles map[string]map[string]string

type config interface {
	Parse() (profiles, error)
}

type fileConfig struct {
	file string
}

func newConfigFromEnv() (config, error) {
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
	return &fileConfig{file: file}, nil
}

func (c *fileConfig) Parse() (profiles, error) {
	if c.file == "" {
		return nil, nil
	}

	log.Printf("Parsing config file %s", c.file)
	f, err := ini.LoadFile(c.file)
	if err != nil {
		return nil, fmt.Errorf("Error parsing config file %q: %v", c.file, err)
	}

	profiles := profiles{}

	for sectionName, section := range f {
		profiles[strings.TrimPrefix(sectionName, "profile ")] = section
	}

	return profiles, nil
}

// sourceProfile returns either the defined source_profile or p if none exists
func sourceProfile(p string, from profiles) string {
	if conf, ok := from[p]; ok {
		if source := conf["source_profile"]; source != "" {
			return source
		}
	}
	return p
}

func formatCredentialError(p string, from profiles, err error) string {
	source := sourceProfile(p, from)
	sourceDescr := p

	// add custom formatting for source_profile
	if source != p {
		sourceDescr = fmt.Sprintf("%s (source profile for %s)", source, p)
	}

	if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
		return fmt.Sprintf(
			"No credentials found for profile %s.\n"+
				"Use 'aws-vault add %s' to set up credentials or 'aws-vault list' to see what credentials exist",
			sourceDescr, source)
	}

	return fmt.Sprintf("Failed to get credentials for %s: %v", err, sourceDescr)
}
