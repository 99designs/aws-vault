package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"strings"

	"github.com/vaughan0/go-ini"
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

func rewriteConfig(f func(line string) (string, bool)) (*os.File, error) {
	srcFile, err := configFile()
	if err != nil {
		return nil, err
	}

	src, err := os.Open(srcFile)
	if err != nil {
		return nil, err
	}
	defer src.Close()

	dest, err := ioutil.TempFile(os.TempDir(), "aws-vault")
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(src)
	for scanner.Scan() {
		if line, write := f(scanner.Text()); write {
			fmt.Fprintln(dest, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return dest, err
	}

	return dest, nil
}
