package vault

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

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
		home, err := os.UserHomeDir()
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
	IncludeProfile          string `ini:"include_profile,omitempty"`
	SSOSession              string `ini:"sso_session,omitempty"`
	SSOStartURL             string `ini:"sso_start_url,omitempty"`
	SSORegion               string `ini:"sso_region,omitempty"`
	SSOAccountID            string `ini:"sso_account_id,omitempty"`
	SSORoleName             string `ini:"sso_role_name,omitempty"`
	WebIdentityTokenFile    string `ini:"web_identity_token_file,omitempty"`
	WebIdentityTokenProcess string `ini:"web_identity_token_process,omitempty"`
	STSRegionalEndpoints    string `ini:"sts_regional_endpoints,omitempty"`
	SessionTags             string `ini:"session_tags,omitempty"`
	TransitiveSessionTags   string `ini:"transitive_session_tags,omitempty"`
	SourceIdentity          string `ini:"source_identity,omitempty"`
	CredentialProcess       string `ini:"credential_process,omitempty"`
	MfaProcess              string `ini:"mfa_process,omitempty"`
}

// SSOSessionSection is a [sso-session] section of the config file
type SSOSessionSection struct {
	Name                  string `ini:"-"`
	SSOStartURL           string `ini:"sso_start_url,omitempty"`
	SSORegion             string `ini:"sso_region,omitempty"`
	SSORegistrationScopes string `ini:"sso_registration_scopes,omitempty"`
}

func (s ProfileSection) IsEmpty() bool {
	s.Name = ""
	return s == ProfileSection{}
}

// ProfileSections returns all the profile sections in the config
func (c *ConfigFile) ProfileSections() []ProfileSection {
	result := []ProfileSection{}

	if c.iniFile == nil {
		return result
	}
	for _, section := range c.iniFile.SectionStrings() {
		if section == defaultSectionName || strings.HasPrefix(section, "profile ") {
			profile, _ := c.ProfileSection(strings.TrimPrefix(section, "profile "))

			// ignore the default profile if it's empty
			if section == defaultSectionName && profile.IsEmpty() {
				continue
			}

			result = append(result, profile)
		} else if strings.HasPrefix(section, "sso-session ") {
			// Not a profile
			continue
		} else {
			log.Printf("Unrecognised ini file section: %s", section)
			continue
		}
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

// SSOSessionSection returns the [sso-session] section with the matching name. If there isn't any,
// an empty sso-session with the provided name is returned, along with false.
func (c *ConfigFile) SSOSessionSection(name string) (SSOSessionSection, bool) {
	ssoSession := SSOSessionSection{
		Name: name,
	}
	if c.iniFile == nil {
		return ssoSession, false
	}
	sectionName := "sso-session " + name
	section, err := c.iniFile.GetSection(sectionName)
	if err != nil {
		return ssoSession, false
	}
	if err = section.MapTo(&ssoSession); err != nil {
		panic(err)
	}
	return ssoSession, true
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
	profileNames := []string{}
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

func NewConfigLoader(baseConfig Config, file *ConfigFile, activeProfile string) *ConfigLoader {
	return &ConfigLoader{
		BaseConfig:    baseConfig,
		File:          file,
		ActiveProfile: activeProfile,
	}
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
	if config.SSOSession == "" {
		config.SSOSession = psection.SSOSession
		if psection.SSOSession != "" {
			// Populate profile with values from [sso-session].
			ssoSection, ok := cl.File.SSOSessionSection(psection.SSOSession)
			if ok {
				config.SSOStartURL = ssoSection.SSOStartURL
				config.SSORegion = ssoSection.SSORegion
				config.SSORegistrationScopes = ssoSection.SSORegistrationScopes
			} else {
				// ignore missing profiles
				log.Printf("[sso-session] '%s' missing in config file", psection.SSOSession)
			}
		}
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
	if config.SourceIdentity == "" {
		config.SourceIdentity = psection.SourceIdentity
	}
	if config.CredentialProcess == "" {
		config.CredentialProcess = psection.CredentialProcess
	}
	if config.MfaProcess == "" {
		config.MfaProcess = psection.MfaProcess
	}
	if sessionTags := psection.SessionTags; sessionTags != "" && config.SessionTags == nil {
		err := config.SetSessionTags(sessionTags)
		if err != nil {
			return fmt.Errorf("Failed to parse session_tags profile setting: %s", err)
		}
	}
	if transitiveSessionTags := psection.TransitiveSessionTags; transitiveSessionTags != "" && config.TransitiveSessionTags == nil {
		config.SetTransitiveSessionTags(transitiveSessionTags)
	}

	if psection.IncludeProfile != "" {
		err := cl.populateFromConfigFile(config, psection.IncludeProfile)
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

	// AWS_ROLE_ARN, AWS_ROLE_SESSION_NAME, AWS_SESSION_TAGS, AWS_TRANSITIVE_TAGS and AWS_SOURCE_IDENTITY only apply to the target profile
	if profile.ProfileName == cl.ActiveProfile {
		if roleARN := os.Getenv("AWS_ROLE_ARN"); roleARN != "" && profile.RoleARN == "" {
			log.Printf("Using role_arn %q from AWS_ROLE_ARN", roleARN)
			profile.RoleARN = roleARN
		}

		if roleSessionName := os.Getenv("AWS_ROLE_SESSION_NAME"); roleSessionName != "" && profile.RoleSessionName == "" {
			log.Printf("Using role_session_name %q from AWS_ROLE_SESSION_NAME", roleSessionName)
			profile.RoleSessionName = roleSessionName
		}

		if sessionTags := os.Getenv("AWS_SESSION_TAGS"); sessionTags != "" && profile.SessionTags == nil {
			err := profile.SetSessionTags(sessionTags)
			if err != nil {
				log.Fatalf("Failed to parse AWS_SESSION_TAGS environment variable: %s", err)
			}
			log.Printf("Using session_tags %v from AWS_SESSION_TAGS", profile.SessionTags)
		}

		if transitiveSessionTags := os.Getenv("AWS_TRANSITIVE_TAGS"); transitiveSessionTags != "" && profile.TransitiveSessionTags == nil {
			profile.SetTransitiveSessionTags(transitiveSessionTags)
			log.Printf("Using transitive_session_tags %v from AWS_TRANSITIVE_TAGS", profile.TransitiveSessionTags)
		}

		if sourceIdentity := os.Getenv("AWS_SOURCE_IDENTITY"); sourceIdentity != "" && profile.SourceIdentity == "" {
			profile.SourceIdentity = sourceIdentity
			log.Printf("Using source_identity %v from AWS_SOURCE_IDENTITY", profile.SourceIdentity)
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

	// MfaProcess specifies external command to run to get an MFA token
	MfaProcess string

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

	// SSOSession specifies the [sso-session] section name.
	SSOSession string

	// SSOStartURL specifies the URL for the AWS IAM Identity Center user portal, legacy option.
	SSOStartURL string

	// SSORegion specifies the region for the AWS IAM Identity Center user portal, legacy option.
	SSORegion string

	// SSORegistrationScopes specifies registration scopes for the AWS IAM Identity Center user portal.
	SSORegistrationScopes string

	// SSOAccountID specifies the AWS account ID for the profile.
	SSOAccountID string

	// SSORoleName specifies the AWS IAM Role name to target.
	SSORoleName string

	// SSOUseStdout specifies that the system browser should not be automatically opened
	SSOUseStdout bool

	// SessionTags specifies assumed role Session Tags
	SessionTags map[string]string

	// TransitiveSessionTags specifies assumed role Transitive Session Tags keys
	TransitiveSessionTags []string

	// SourceIdentity specifies assumed role Source Identity
	SourceIdentity string

	// CredentialProcess specifies external command to run to get an AWS credential
	CredentialProcess string
}

// SetSessionTags parses a comma separated key=vaue string and sets Config.SessionTags map
func (c *Config) SetSessionTags(s string) error {
	c.SessionTags = make(map[string]string)
	for _, tag := range strings.Split(s, ",") {
		kvPair := strings.SplitN(tag, "=", 2)
		if len(kvPair) != 2 {
			return errors.New("session tags string must be <key1>=<value1>,[<key2>=<value2>[,...]]")
		}
		c.SessionTags[strings.TrimSpace(kvPair[0])] = strings.TrimSpace(kvPair[1])
	}

	return nil
}

// SetTransitiveSessionTags parses a comma separated string and sets Config.TransitiveSessionTags
func (c *Config) SetTransitiveSessionTags(s string) {
	for _, tag := range strings.Split(s, ",") {
		if tag = strings.TrimSpace(tag); tag != "" {
			c.TransitiveSessionTags = append(c.TransitiveSessionTags, tag)
		}
	}
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

func (c *Config) HasSSOSession() bool {
	return c.SSOSession != ""
}

func (c *Config) HasSSOStartURL() bool {
	return c.SSOStartURL != ""
}

func (c *Config) HasWebIdentity() bool {
	return c.WebIdentityTokenFile != "" || c.WebIdentityTokenProcess != ""
}

func (c *Config) HasCredentialProcess() bool {
	return c.CredentialProcess != ""
}

// CanUseGetSessionToken determines if GetSessionToken should be used, and if not returns a reason
func (c *Config) CanUseGetSessionToken() (bool, string) {
	if !UseSession {
		return false, "sessions are disabled"
	}

	if c.IsChained() {
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
	}
	return c.NonChainedGetSessionTokenDuration
}
