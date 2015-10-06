package main

import (
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"

	ini "github.com/vaughan0/go-ini"
)

type profiles map[string]map[string]string

func configFile() (file string, err error) {
	file = os.Getenv("AWS_CONFIG_FILE")
	if file == "" {
		usr, err := user.Current()
		if err != nil {
			return file, err
		}
		file = usr.HomeDir + "/.aws/config"
	}
	return file, err
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

func writeProfiles(dest *os.File, profiles profiles) error {
	for profile, vals := range profiles {
		fmt.Fprintf(dest, "[profile %s]\n", profile)
		for k, v := range vals {
			fmt.Fprintf(dest, "%s = %s\n", k, v)
		}
		fmt.Fprintln(dest, "")
	}
	return dest.Sync()
}
