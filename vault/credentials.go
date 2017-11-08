package vault

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/go-ini/ini"
	homedir "github.com/mitchellh/go-homedir"
)

type SharedCredentials struct {
	AccessKeyID     string `ini:"aws_access_key_id"`
	SecretAccessKey string `ini:"aws_secret_access_key"`
}

func GetSharedCredentialsFile() (string, error) {
	file := os.Getenv("AWS_SHARED_CREDENTIALS_FILE")
	if file == "" {
		home, err := homedir.Dir()
		if err != nil {
			return "", err
		}
		file = filepath.Join(home, "/.aws/credentials")
	}
	return file, nil
}

func ReadCredentialsFromFile(file string, profile string) (cred SharedCredentials, err error) {
	log.Printf("Parsing credential file %s", file)
	iniFile, err := ini.Load(file)
	if err != nil {
		return cred, fmt.Errorf("Error parsing credential file %q: %v", file, err)
	}
	for _, sectionName := range iniFile.SectionStrings() {
		if sectionName == profile {
			section, err := iniFile.GetSection(sectionName)
			if err != nil {
				return cred, err
			}
			if err = section.MapTo(&cred); err != nil {
				return cred, err
			}
			return cred, nil
		}
	}

	return cred, fmt.Errorf("Failed to find profile %q", profile)
}

func WriteCredentialsToFile(file string, profile string, creds credentials.Value) error {
	var cfg *ini.File
	var err error

	if _, statErr := os.Stat(file); os.IsNotExist(statErr) {
		cfg = ini.Empty()
	} else {
		cfg, err = ini.Load(file)
		if err != nil {
			return err
		}
	}

	section := cfg.Section(profile)
	_, err = section.NewKey("aws_access_key_id", creds.AccessKeyID)
	if err != nil {
		return err
	}
	_, err = section.NewKey("aws_secret_access_key", creds.SecretAccessKey)
	if err != nil {
		return err
	}

	return cfg.SaveTo(file)
}
