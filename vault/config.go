package vault

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/99designs/aws-vault/prompt"
	"github.com/mitchellh/go-homedir"
	ini "gopkg.in/ini.v1"
)

const (
	MaxSessionDuration    = time.Hour * 36
	MinSessionDuration    = time.Minute * 15
	MinAssumeRoleDuration = time.Minute * 15
	MaxAssumeRoleDuration = time.Hour * 12

	DefaultSessionDuration    = time.Hour * 4
	DefaultAssumeRoleDuration = time.Minute * 15
)

func init() {
	ini.PrettyFormat = false
}

// ConfigFile is an abstraction over what is in ~/.aws/config
type ConfigFile struct {
	Path    string
	iniFile *ini.File
}

// ConfigPath returns either $AWS_CONFIG_FILE or ~/.aws/config
func ConfigPath() (string, error) {
	file := os.Getenv("AWS_CONFIG_FILE")
	if file == "" {
		home, err := homedir.Dir()
		if err != nil {
			return "", err
		}
		file = filepath.Join(home, "/.aws/config")
	} else {
		log.Printf("Using AWS_CONFIG_FILE value: %s", file)
	}
	return file, nil
}

// CreateConfig will create the config directory and file if they do not exist
func CreateConfig() error {
	file, err := ConfigPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(file)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		os.Mkdir(dir, 0700)
		log.Printf("Config directory %s created", dir)
	}
	if _, err := os.Stat(file); os.IsNotExist(err) {
		newFile, err := os.Create(file)
		if err != nil {
			log.Printf("Config file %s not created", file)
			return err
		}
		newFile.Close()
		log.Printf("Config file %s created", file)
	}
	return nil
}

// LoadConfig loads and parses a config file. No error is returned if the file doesn't exist
func LoadConfig(path string) (*ConfigFile, error) {
	config := &ConfigFile{
		Path: path,
	}
	if _, err := os.Stat(path); err == nil {
		if parseErr := config.parseFile(); parseErr != nil {
			return nil, parseErr
		}
	} else {
		log.Printf("Config file %s doesn't exist so lets create it", path)
		err := CreateConfig()
		if err != nil {
			return nil, err
		}
		if parseErr := config.parseFile(); parseErr != nil {
			return nil, parseErr
		}
	}
	return config, nil
}

// LoadConfigFromEnv finds the config file from the environment
func LoadConfigFromEnv() (*ConfigFile, error) {
	file, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	log.Printf("Loading config file %s", file)
	return LoadConfig(file)
}

func (c *ConfigFile) parseFile() error {
	log.Printf("Parsing config file %s", c.Path)
	f, err := ini.LoadSources(ini.LoadOptions{
		AllowNestedValues: true,
	}, c.Path)
	if err != nil {
		return fmt.Errorf("Error parsing config file %q: %v", c.Path, err)
	}
	c.iniFile = f
	return nil
}

// ProfileSection is a profile section of config
type ProfileSection struct {
	Name            string `ini:"-"`
	MfaSerial       string `ini:"mfa_serial,omitempty"`
	RoleARN         string `ini:"role_arn,omitempty"`
	ExternalID      string `ini:"external_id,omitempty"`
	Region          string `ini:"region,omitempty"`
	RoleSessionName string `ini:"role_session_name,omitempty"`
	SourceProfile   string `ini:"source_profile,omitempty"`
	ParentProfile   string `ini:"parent_profile,omitempty"`
}

// Profiles returns all the profiles in the config
func (c *ConfigFile) profiles() []ProfileSection {
	var result []ProfileSection

	if c.iniFile == nil {
		return result
	}

	for _, section := range c.iniFile.SectionStrings() {
		if section != "DEFAULT" {
			profile, _ := c.ProfileSection(strings.TrimPrefix(section, "profile "))
			result = append(result, profile)
		}
	}

	return result
}

// Profile returns the profile section with the matching name. If there isn't any,
// an empty profile with the provided name is returned, along with false.
func (c *ConfigFile) ProfileSection(name string) (ProfileSection, bool) {
	profile := ProfileSection{
		Name: name,
	}
	if c.iniFile == nil {
		return profile, false
	}
	// default profile name has a slightly different section format
	sectionName := "profile " + name
	if name == "default" {
		sectionName = "default"
	}
	section, err := c.iniFile.GetSection(sectionName)
	if err != nil {
		return profile, false
	}
	if err = section.MapTo(&profile); err != nil {
		panic(err)
	}
	return profile, true
}

// Add the profile to the configuration file
func (c *ConfigFile) Add(profile ProfileSection) error {
	if c.iniFile == nil {
		return errors.New("No iniFile to add to")
	}
	// default profile name has a slightly different section format
	sectionName := "profile " + profile.Name
	if profile.Name == "default" {
		sectionName = "default"
	}
	section, err := c.iniFile.NewSection(sectionName)
	if err != nil {
		return fmt.Errorf("Error creating section %q: %v", profile.Name, err)
	}
	if err = section.ReflectFrom(&profile); err != nil {
		return fmt.Errorf("Error mapping profile to ini file: %v", err)
	}
	return c.iniFile.SaveTo(c.Path)
}

// FormatCredentialError formats errors with some user friendly context
func (c *ConfigFile) FormatCredentialError(err error, profileName string) string {
	// profile, _ := c.Profile(profileName)

	sourceDescr := profileName
	// if profile.CredentialName != profileName {
	// 	sourceDescr = fmt.Sprintf("%s (source profile for %s)", profile.CredentialName, profileName)
	// }

	// if awsErr, ok := err.(awserr.Error); ok && awsErr.Code() == "NoCredentialProviders" {
	// 	return fmt.Sprintf(
	// 		"No credentials found for profile %s.\n"+
	// 			"Use 'aws-vault add %s' to set up credentials or 'aws-vault list' to see what credentials exist",
	// 		sourceDescr, profile.CredentialName)
	// }

	return fmt.Sprintf("Failed to get credentials for %s: %v", sourceDescr, err)
}

// ProfileNames returns a slice of profile names from the AWS config
func (c *ConfigFile) ProfileNames() []string {
	var profileNames []string
	for _, profile := range c.profiles() {
		profileNames = append(profileNames, profile.Name)
	}
	return profileNames
}

type CliFlags struct {
	MfaSerial string
}

type ConfigLoader struct {
	File            *ConfigFile
	visitedProfiles []string
}

func (c *ConfigLoader) visitProfile(name string) bool {
	for _, p := range c.visitedProfiles {
		if p == name {
			return false
		}
	}
	c.visitedProfiles = append(c.visitedProfiles, name)
	return true
}

func (c *ConfigLoader) resetLoopDetection() {
	c.visitedProfiles = []string{}
}

func (c *ConfigLoader) populateFromDefaults(config *Config) {
	if config.AssumeRoleDuration == 0 {
		config.AssumeRoleDuration = DefaultAssumeRoleDuration
	}
	if config.SessionDuration == 0 {
		config.SessionDuration = DefaultSessionDuration
	}
}

func (c *ConfigLoader) populateFromConfigFile(config *Config, profileName string) error {
	if !c.visitProfile(profileName) {
		fmt.Errorf("Loop detected in config file for profile '%s'", profileName)
	}

	psection, ok := c.File.ProfileSection(profileName)
	if !ok {
		fmt.Errorf("Can't find profile '%s' in config file", profileName)
	}

	if config.MfaSerial == "" {
		config.MfaSerial = psection.MfaSerial
	}
	if config.RoleARN == "" {
		config.RoleARN = psection.RoleARN
	}
	if config.ExternalID == "" {
		config.ExternalID = psection.ExternalID
	}
	if config.Region == "" {
		config.Region = psection.Region
	}
	if config.RoleSessionName == "" {
		config.RoleSessionName = psection.RoleSessionName
	}

	if psection.SourceProfile != "" {
		config.CredentialName = psection.SourceProfile
	} else {
		config.CredentialName = profileName
	}

	if psection.ParentProfile != "" {
		err := c.populateFromConfigFile(config, psection.ParentProfile)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *ConfigLoader) populateFromEnv(profile *Config) {
	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" && profile.Region == "" {
		log.Printf("Using region %q from AWS_DEFAULT_REGION", region)
		profile.Region = region
	}

	if region := os.Getenv("AWS_REGION"); region != "" && profile.Region == "" {
		log.Printf("Using region %q from AWS_REGION", region)
		profile.Region = region
	}

	if mfaSerial := os.Getenv("AWS_MFA_SERIAL"); mfaSerial != "" && profile.MfaSerial == "" {
		log.Printf("Using mfa_serial %q from AWS_MFA_SERIAL", mfaSerial)
		profile.MfaSerial = mfaSerial
	}
}

func (c *ConfigLoader) LoadFromProfile(profileName string, config *Config) error {
	config.ProfileName = profileName
	c.populateFromDefaults(config)
	c.populateFromEnv(config)

	c.resetLoopDetection()
	err := c.populateFromConfigFile(config, profileName)
	if err != nil {
		return err
	}

	err = config.Validate()
	if err != nil {
		return err
	}

	return nil
}

type Config struct {
	ProfileName    string
	CredentialName string

	MfaSerial       string
	RoleARN         string
	ExternalID      string
	Region          string
	RoleSessionName string

	SessionDuration    time.Duration
	AssumeRoleDuration time.Duration
	MfaToken           string
	MfaPrompt          prompt.PromptFunc
	NoSession          bool
}

func (c *Config) Validate() error {
	if c.SessionDuration < MinSessionDuration {
		return errors.New("Minimum session duration is " + MinSessionDuration.String())
	} else if c.SessionDuration > MaxSessionDuration {
		return errors.New("Maximum session duration is " + MaxSessionDuration.String())
	}
	if c.AssumeRoleDuration < MinAssumeRoleDuration {
		return errors.New("Minimum duration for assumed roles is " + MinAssumeRoleDuration.String())
	} else if c.AssumeRoleDuration > MaxAssumeRoleDuration {
		return errors.New("Maximum duration for assumed roles is " + MaxAssumeRoleDuration.String())
	}

	return nil
}
