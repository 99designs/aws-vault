package vault

import (
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/99designs/aws-vault/Godeps/_workspace/src/github.com/vaughan0/go-ini"
)

var AWSConfigFile string

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

type AWSProfile struct {
	Name          string
	Region        string
	MFASerial     string
	RoleARN       string
	SourceProfile string
}

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
	err = fmt.Errorf(
		"Profile '%s' not found in %s",
		name,
		AWSConfigFile,
	)
	return AWSProfile{}, err
}
