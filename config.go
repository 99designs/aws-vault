package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
