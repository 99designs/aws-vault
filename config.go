package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"

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
		usr, err := user.Current()
		if err != nil {
			return nil, err
		}
		file = usr.HomeDir + "/.aws/config"
	}
	return &fileConfig{file: file}, nil
}

func (c *fileConfig) Parse() (profiles, error) {
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
