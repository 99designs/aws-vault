package vault

import (
	"os"
	"os/user"
	"strings"

	"github.com/vaughan0/go-ini"
)

type AWSProfile struct {
	Region        string
	MFASerial     string
	RoleARN       string
	SourceProfile string
}

func LoadAWSProfiles() (map[string]AWSProfile, error) {
	configFile := os.Getenv("AWS_CONFIG_FILE")
	if configFile == "" {
		usr, err := user.Current()
		if err != nil {
			return nil, err
		}
		configFile = usr.HomeDir + "/.aws/config"
	}

	f, err := ini.LoadFile(configFile)
	if err != nil {
		return nil, err
	}

	profiles := map[string]AWSProfile{}
	for name, section := range f {
		profiles[strings.TrimPrefix(name, "profile ")] = AWSProfile{
			Region:        section["region"],
			MFASerial:     section["mfa_serial"],
			RoleARN:       section["role_arn"],
			SourceProfile: section["source_profile"],
		}
	}

	return profiles, nil
}
