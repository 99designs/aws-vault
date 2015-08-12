package vault

import (
	"errors"
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

var AWSConfigFile string

var ErrProfileNotFound = errors.New("Profile not found")

func LoadAWSProfile(name string) (AWSProfile, error) {
	f, err := ini.LoadFile(AWSConfigFile)
	if err != nil {
		return AWSProfile{}, err
	}
	for sectionName, section := range f {
		if strings.TrimPrefix(sectionName, "profile ") == name {
			return AWSProfile{
				Region:        section["region"],
				MFASerial:     section["mfa_serial"],
				RoleARN:       section["role_arn"],
				SourceProfile: section["source_profile"],
			}, nil
		}
	}
	return AWSProfile{}, ErrProfileNotFound
}

func init() {
	AWSConfigFile = os.Getenv("AWS_CONFIG_FILE")
	if AWSConfigFile == "" {
		usr, err := user.Current()
		if err != nil {
			panic(err)
		}
		AWSConfigFile = usr.HomeDir + "/.aws/config"
	}
}
