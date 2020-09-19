package vault

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mitchellh/go-homedir"
	ini "gopkg.in/ini.v1"
)

const (
	// DefaultSessionDuration is the default duration for GetSessionToken or AssumeRole sessions
	DefaultSessionDuration = time.Hour * 1

	// DefaultChainedSessionDuration is the default duration for GetSessionToken sessions when chaining
	DefaultChainedSessionDuration = time.Hour * 8

	defaultSectionName          = "default"
	roleChainingMaximumDuration = 1 * time.Hour
)

// UseSession will disable the use of GetSessionToken when set to false
var UseSession = true

func init() {
	ini.PrettyFormat = false
}

// ConfigFile is an abstraction over what is in ~/.aws/config
type ConfigFile struct {
	Path    string
	iniFile *ini.File
}

// configPath returns either $AWS_CONFIG_FILE or ~/.aws/config
func configPath() (string, error) {
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

// createConfigFilesIfMissing will create the config directory and file if they do not exist
func createConfigFilesIfMissing() error {
	file, err := configPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(file)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.Mkdir(dir, 0700)
		if err != nil {
			return err
		}
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
		err := createConfigFilesIfMissing()
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
	file, err := configPath()
	if err != nil {
		return nil, err
	}

	log.Printf("Loading config file %s", file)
	return LoadConfig(file)
}

func (c *ConfigFile) parseFile() error {
	log.Printf("Parsing config file %s", c.Path)

	f, err := ini.LoadSources(ini.LoadOptions{
		AllowNestedValues:   true,
		InsensitiveSections: false,
		InsensitiveKeys:     true,
	}, c.Path)
	if err != nil {
		return fmt.Errorf("Error parsing config file %s: %w", c.Path, err)
	}
	c.iniFile = f
	return nil
}

// ProfileSection is a profile section of the config file
type ProfileSection struct {
	Name                    string `ini:"-"`
	MfaSerial               string `ini:"mfa_serial,omitempty"`
	RoleARN                 string `ini:"role_arn,omitempty"`
	ExternalID              string `ini:"external_id,omitempty"`
	Region                  string `ini:"region,omitempty"`
	RoleSessionName         string `ini:"role_session_name,omitempty"`
	DurationSeconds         uint   `ini:"duration_seconds,omitempty"`
	SourceProfile           string `ini:"source_profile,omitempty"`
	ParentProfile           string `ini:"parent_profile,omitempty"` // deprecated
	IncludeProfile          string `ini:"include_profile,omitempty"`
	SSOStartURL             string `ini:"sso_start_url,omitempty"`
	SSORegion               string `ini:"sso_region,omitempty"`
	SSOAccountID            string `ini:"sso_account_id,omitempty"`
	SSORoleName             string `ini:"sso_role_name,omitempty"`
	WebIdentityTokenFile    string `ini:"web_identity_token_file,omitempty"`
	WebIdentityTokenProcess string `ini:"web_identity_token_process,omitempty"`
	STSRegionalEndpoints    string `ini:"sts_regional_endpoints,omitempty"`
}

func (s ProfileSection) IsEmpty() bool {
	s.Name = ""
	return s == ProfileSection{}
}

// ProfileSections returns all the profile sections in the config
func (c *ConfigFile) ProfileSections() []ProfileSection {
	var result []ProfileSection

	if c.iniFile == nil {
		return result
	}

	for _, section := range c.iniFile.SectionStrings() {
		if section != defaultSectionName && !strings.HasPrefix(section, "profile ") {
			log.Printf("Unrecognised ini file section: %s", section)
			continue
		}

		profile, _ := c.ProfileSection(strings.TrimPrefix(section, "profile "))

		// ignore the default profile if it's empty
		if section == defaultSectionName && profile.IsEmpty() {
			continue
		}

		result = append(result, profile)
	}

	return result
}

// ProfileSection returns the profile section with the matching name. If there isn't any,
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
	if name == defaultSectionName {
		sectionName = defaultSectionName
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

func (c *ConfigFile) Save() error {
	return c.iniFile.SaveTo(c.Path)
}

// Add the profile to the configuration file
func (c *ConfigFile) Add(profile ProfileSection) error {
	if c.iniFile == nil {
		return errors.New("No iniFile to add to")
	}
	// default profile name has a slightly different section format
	sectionName := "profile " + profile.Name
	if profile.Name == defaultSectionName {
		sectionName = defaultSectionName
	}
	section, err := c.iniFile.NewSection(sectionName)
	if err != nil {
		return fmt.Errorf("Error creating section %q: %v", profile.Name, err)
	}
	if err = section.ReflectFrom(&profile); err != nil {
		return fmt.Errorf("Error mapping profile to ini file: %v", err)
	}
	return c.Save()
}

// ProfileNames returns a slice of profile names from the AWS config
func (c *ConfigFile) ProfileNames() []string {
	var profileNames []string
	for _, profile := range c.ProfileSections() {
		profileNames = append(profileNames, profile.Name)
	}
	return profileNames
}

// ConfigLoader loads config from configfile and environment variables
type ConfigLoader struct {
	BaseConfig      Config
	File            *ConfigFile
	ActiveProfile   string
	visitedProfiles []string
}

func (cl *ConfigLoader) visitProfile(name string) bool {
	for _, p := range cl.visitedProfiles {
		if p == name {
			return false
		}
	}
	cl.visitedProfiles = append(cl.visitedProfiles, name)
	return true
}

func (cl *ConfigLoader) resetLoopDetection() {
	cl.visitedProfiles = []string{}
}

func (cl *ConfigLoader) populateFromDefaults(config *Config) {
	if config.AssumeRoleDuration == 0 {
		config.AssumeRoleDuration = DefaultSessionDuration
	}
	if config.GetFederationTokenDuration == 0 {
		config.GetFederationTokenDuration = DefaultSessionDuration
	}
	if config.NonChainedGetSessionTokenDuration == 0 {
		config.NonChainedGetSessionTokenDuration = DefaultSessionDuration
	}
	if config.ChainedGetSessionTokenDuration == 0 {
		config.ChainedGetSessionTokenDuration = DefaultChainedSessionDuration
	}
}

func (cl *ConfigLoader) populateFromConfigFile(config *Config, profileName string) error {
	if !cl.visitProfile(profileName) {
		return fmt.Errorf("Loop detected in config file for profile '%s'", profileName)
	}

	psection, ok := cl.File.ProfileSection(profileName)
	if !ok {
		// ignore missing profiles
		log.Printf("Profile '%s' missing in config file", profileName)
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
	if config.AssumeRoleDuration == 0 {
		config.AssumeRoleDuration = time.Duration(psection.DurationSeconds) * time.Second
	}
	if config.SourceProfileName == "" {
		config.SourceProfileName = psection.SourceProfile
	}
	if config.SSOStartURL == "" {
		config.SSOStartURL = psection.SSOStartURL
	}
	if config.SSORegion == "" {
		config.SSORegion = psection.SSORegion
	}
	if config.SSOAccountID == "" {
		config.SSOAccountID = psection.SSOAccountID
	}
	if config.SSORoleName == "" {
		config.SSORoleName = psection.SSORoleName
	}
	if config.WebIdentityTokenFile == "" {
		config.WebIdentityTokenFile = psection.WebIdentityTokenFile
	}
	if config.WebIdentityTokenProcess == "" {
		config.WebIdentityTokenProcess = psection.WebIdentityTokenProcess
	}
	if config.STSRegionalEndpoints == "" {
		config.STSRegionalEndpoints = psection.STSRegionalEndpoints
	}

	if psection.ParentProfile != "" {
		fmt.Fprint(os.Stderr, "Warning: parent_profile is deprecated, please use include_profile instead in your AWS config\n")
	}

	if psection.IncludeProfile != "" {
		err := cl.populateFromConfigFile(config, psection.IncludeProfile)
		if err != nil {
			return err
		}
	} else if psection.ParentProfile != "" {
		err := cl.populateFromConfigFile(config, psection.ParentProfile)
		if err != nil {
			return err
		}
	} else if profileName != defaultSectionName {
		err := cl.populateFromConfigFile(config, defaultSectionName)
		if err != nil {
			return err
		}
	}

	// Ignore source_profile if it recursively refers to the profile
	if config.SourceProfileName == config.ProfileName {
		config.SourceProfileName = ""
	}

	return nil
}

func (cl *ConfigLoader) populateFromEnv(profile *Config) {
	if region := os.Getenv("AWS_REGION"); region != "" && profile.Region == "" {
		log.Printf("Using region %q from AWS_REGION", region)
		profile.Region = region
	}

	if region := os.Getenv("AWS_DEFAULT_REGION"); region != "" && profile.Region == "" {
		log.Printf("Using region %q from AWS_DEFAULT_REGION", region)
		profile.Region = region
	}

	if stsRegionalEndpoints := os.Getenv("AWS_STS_REGIONAL_ENDPOINTS"); stsRegionalEndpoints != "" && profile.STSRegionalEndpoints == "" {
		log.Printf("Using %q from AWS_STS_REGIONAL_ENDPOINTS", stsRegionalEndpoints)
		profile.STSRegionalEndpoints = stsRegionalEndpoints
	}

	if mfaSerial := os.Getenv("AWS_MFA_SERIAL"); mfaSerial != "" && profile.MfaSerial == "" {
		log.Printf("Using mfa_serial %q from AWS_MFA_SERIAL", mfaSerial)
		profile.MfaSerial = mfaSerial
	}

	var err error
	if assumeRoleTTL := os.Getenv("AWS_ASSUME_ROLE_TTL"); assumeRoleTTL != "" && profile.AssumeRoleDuration == 0 {
		profile.AssumeRoleDuration, err = time.ParseDuration(assumeRoleTTL)
		if err == nil {
			log.Printf("Using duration_seconds %q from AWS_ASSUME_ROLE_TTL", profile.AssumeRoleDuration)
		}
	}

	if sessionTTL := os.Getenv("AWS_SESSION_TOKEN_TTL"); sessionTTL != "" && profile.NonChainedGetSessionTokenDuration == 0 {
		profile.NonChainedGetSessionTokenDuration, err = time.ParseDuration(sessionTTL)
		if err == nil {
			log.Printf("Using a session duration of %q from AWS_SESSION_TOKEN_TTL", profile.NonChainedGetSessionTokenDuration)
		}
	}

	if sessionTTL := os.Getenv("AWS_CHAINED_SESSION_TOKEN_TTL"); sessionTTL != "" && profile.ChainedGetSessionTokenDuration == 0 {
		profile.ChainedGetSessionTokenDuration, err = time.ParseDuration(sessionTTL)
		if err == nil {
			log.Printf("Using a cached MFA session duration of %q from AWS_CACHED_SESSION_TOKEN_TTL", profile.ChainedGetSessionTokenDuration)
		}
	}

	if federationTokenTTL := os.Getenv("AWS_FEDERATION_TOKEN_TTL"); federationTokenTTL != "" && profile.GetFederationTokenDuration == 0 {
		profile.GetFederationTokenDuration, err = time.ParseDuration(federationTokenTTL)
		if err == nil {
			log.Printf("Using a session duration of %q from AWS_FEDERATION_TOKEN_TTL", profile.GetFederationTokenDuration)
		}
	}

	// AWS_ROLE_ARN and AWS_ROLE_SESSION_NAME only apply to the target profile
	if profile.ProfileName == cl.ActiveProfile {
		if roleARN := os.Getenv("AWS_ROLE_ARN"); roleARN != "" && profile.RoleARN == "" {
			log.Printf("Using role_arn %q from AWS_ROLE_ARN", roleARN)
			profile.RoleARN = roleARN
		}

		if roleSessionName := os.Getenv("AWS_ROLE_SESSION_NAME"); roleSessionName != "" && profile.RoleSessionName == "" {
			log.Printf("Using role_session_name %q from AWS_ROLE_SESSION_NAME", roleSessionName)
			profile.RoleSessionName = roleSessionName
		}
	}
}

func (cl *ConfigLoader) hydrateSourceConfig(config *Config) error {
	if config.SourceProfileName != "" {
		sc, err := cl.LoadFromProfile(config.SourceProfileName)
		if err != nil {
			return err
		}
		sc.ChainedFromProfile = config
		config.SourceProfile = sc
	}
	return nil
}

// LoadFromProfile loads the profile from the config file and environment variables into config
func (cl *ConfigLoader) LoadFromProfile(profileName string) (*Config, error) {
	config := cl.BaseConfig
	config.ProfileName = profileName
	cl.populateFromEnv(&config)

	cl.resetLoopDetection()
	err := cl.populateFromConfigFile(&config, profileName)
	if err != nil {
		return nil, err
	}

	cl.populateFromDefaults(&config)

	err = cl.hydrateSourceConfig(&config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}

// Config is a collection of configuration options for creating temporary credentials
type Config struct {
	// ProfileName specifies the name of the profile config
	ProfileName string

	// SourceProfile is the profile where credentials come from
	SourceProfileName string

	// SourceProfile is the profile where credentials come from
	SourceProfile *Config

	// ChainedFromProfile is the profile that used this profile as it's source profile
	ChainedFromProfile *Config

	// Region is the AWS region
	Region string

	// STSRegionalEndpoints sets STS endpoint resolution logic, must be "regional" or "legacy"
	STSRegionalEndpoints string

	// Mfa config
	MfaSerial       string
	MfaToken        string
	MfaPromptMethod string

	// AssumeRole config
	RoleARN         string
	RoleSessionName string
	ExternalID      string

	// AssumeRoleWithWebIdentity config
	WebIdentityTokenFile    string
	WebIdentityTokenProcess string

	// GetSessionTokenDuration specifies the wanted duration for credentials generated with AssumeRole
	AssumeRoleDuration time.Duration

	// NonChainedGetSessionTokenDuration specifies the wanted duration for credentials generated with GetSessionToken
	NonChainedGetSessionTokenDuration time.Duration

	// ChainedGetSessionTokenDuration specifies the wanted duration for credentials generated with GetSessionToken when chaining
	ChainedGetSessionTokenDuration time.Duration

	// GetFederationTokenDuration specifies the wanted duration for credentials generated with GetFederationToken
	GetFederationTokenDuration time.Duration

	// SSOStartURL specifies the URL for the AWS SSO user portal.
	SSOStartURL string

	// SSORegion specifies the region for the AWS SSO user portal.
	SSORegion string

	// SSOAccountID specifies the AWS account ID for the profile.
	SSOAccountID string

	// SSORoleName specifies the AWS SSO Role name to target.
	SSORoleName string
}

func (c *Config) IsChained() bool {
	return c.ChainedFromProfile != nil
}

func (c *Config) HasSourceProfile() bool {
	return c.SourceProfile != nil
}

func (c *Config) HasMfaSerial() bool {
	return c.MfaSerial != ""
}

func (c *Config) HasRole() bool {
	return c.RoleARN != ""
}

func (c *Config) HasSSOStartURL() bool {
	return c.SSOStartURL != ""
}

func (c *Config) HasWebIdentityTokenFile() bool {
	return c.WebIdentityTokenFile != ""
}

func (c *Config) HasWebIdentityTokenProcess() bool {
	return c.WebIdentityTokenProcess != ""
}

// CanUseGetSessionToken determines if GetSessionToken should be used, and if not returns a reason
func (c *Config) CanUseGetSessionToken() (bool, string) {
	if !UseSession {
		return false, "disabled"
	}

	if c.HasRole() {
		if c.AssumeRoleDuration > roleChainingMaximumDuration {
			return false, fmt.Sprintf("duration %s is greater than the AWS maximum %s for chaining MFA", c.AssumeRoleDuration, roleChainingMaximumDuration)
		}
	} else if c.IsChained() {
		if !c.ChainedFromProfile.HasMfaSerial() {
			return false, fmt.Sprintf("profile '%s' has no MFA serial defined", c.ChainedFromProfile.ProfileName)
		}

		if !c.HasMfaSerial() && c.ChainedFromProfile.HasMfaSerial() {
			return false, fmt.Sprintf("profile '%s' has no MFA serial defined", c.ProfileName)
		}

		if c.ChainedFromProfile.MfaSerial != c.MfaSerial {
			return false, fmt.Sprintf("MFA serial doesn't match profile '%s'", c.ChainedFromProfile.ProfileName)
		}

		if c.ChainedFromProfile.AssumeRoleDuration > roleChainingMaximumDuration {
			return false, fmt.Sprintf("duration %s in profile '%s' is greater than the AWS maximum %s for chaining MFA", c.ChainedFromProfile.AssumeRoleDuration, c.ChainedFromProfile.ProfileName, roleChainingMaximumDuration)
		}
	}

	return true, ""
}

func (c *Config) GetSessionTokenDuration() time.Duration {
	if c.IsChained() {
		return c.ChainedGetSessionTokenDuration
	} else {
		return c.NonChainedGetSessionTokenDuration
	}
}
