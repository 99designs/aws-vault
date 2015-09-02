package main

import (
	"log"
	"os"
	"os/user"
	"strings"

	"github.com/vaughan0/go-ini"
)

type profiles map[string]map[string]string

func parseProfiles() (profiles, error) {
	file := os.Getenv("AWS_CONFIG_FILE")
	if file == "" {
		usr, err := user.Current()
		if err != nil {
			return nil, err
		}
		file = usr.HomeDir + "/.aws/config"
	}

	log.Printf("Parsing config file %s", file)
	f, err := ini.LoadFile(file)
	if err != nil {
		return nil, err
	}

	profiles := profiles{}

	for sectionName, section := range f {
		profiles[strings.TrimPrefix(sectionName, "profile ")] = section
	}

	return profiles, nil
}

func (p profiles) sourceProfile(profile string) string {
	if conf, ok := p[profile]; ok {
		if source := conf["source_profile"]; source != "" {
			return source
		}
	}
	return profile
}
