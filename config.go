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

func addProfile(profile string) error {
	file, err := configFile()
	if err != nil {
		return err
	}

	f, err := os.OpenFile(file, os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err = f.WriteString(fmt.Sprintf("\n[profile %s]\n\n", profile)); err != nil {
		return err
	}

	return nil
}

func profileExists(profile string) (bool, error) {
	profiles, err := parseProfiles()
	if err != nil {
		return false, err
	}

	_, exists := profiles[profile]
	return exists, nil
}

func configFile() (string, error) {
	file := os.Getenv("AWS_CONFIG_FILE")
	if file == "" {
		usr, err := user.Current()
		if err != nil {
			return "", err
		}
		file = usr.HomeDir + "/.aws/config"
	}
	return file, nil
}

func parseProfiles() (profiles, error) {
	file, err := configFile()
	if err != nil {
		return nil, err
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
