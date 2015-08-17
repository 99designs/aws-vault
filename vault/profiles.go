package vault

import (
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/vaughan0/go-ini"
	"github.com/99designs/aws-vault/keyring"
)

var DefaultProfileConfig = &ProfileConfig{}

type ProfileConfig struct {
	File     string
	parsed   bool
	profiles map[string]*Profile
}

func NewProfileConfig(profiles ...*Profile) *ProfileConfig {
	c := &ProfileConfig{
		File:     "map",
		profiles: map[string]*Profile{},
		parsed:   true,
	}

	for _, p := range profiles {
		c.profiles[p.Name] = p
	}

	return c
}

type Profile struct {
	Name          string
	Region        string
	MFASerial     string
	RoleARN       string
	SourceProfile *Profile
}

func defaultConfigFile() (string, error) {
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

func (c *ProfileConfig) parse() error {
	if c.File == "" {
		if file, err := defaultConfigFile(); err != nil {
			return err
		} else {
			c.File = file
		}
	}

	c.profiles = map[string]*Profile{}
	sources := map[string]string{}
	f, err := ini.LoadFile(c.File)
	if err != nil {
		return err
	}

	// read default and profiles
	for sectionName, section := range f {
		name := strings.TrimPrefix(sectionName, "profile ")
		c.profiles[name] = &Profile{
			Name:      name,
			Region:    section["region"],
			MFASerial: section["mfa_serial"],
			RoleARN:   section["role_arn"],
		}
		if section["source_profile"] != "" {
			sources[name] = section["source_profile"]
		}
	}

	// link source_profile stanzas
	for k, v := range sources {
		p, ok := c.profiles[v]
		if !ok {
			return fmt.Errorf("Profile %s references a non-existent source %s", k, v)
		}
		c.profiles[k].SourceProfile = p
	}
	return nil
}

func (c *ProfileConfig) Profile(name string) (*Profile, error) {
	if !c.parsed {
		if err := c.parse(); err != nil {
			return nil, err
		}
		c.parsed = true
	}
	profile, ok := c.profiles[name]
	if !ok {
		return &Profile{Name: name}, fmt.Errorf(
			"Profile '%s' not found in %s",
			name,
			c.File,
		)
	}
	return profile, nil
}

func (p *Profile) Keyring(k keyring.Keyring) *ProfileKeyring {
	return &ProfileKeyring{k, p}
}
