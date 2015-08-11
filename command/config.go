package command

import (
	"flag"
	"os"
)

var defaultProfile string = "default"

type config struct {
	*flag.FlagSet
	Profile string
}

func parseFlags(args []string, f func(flagSet *flag.FlagSet)) (*config, error) {
	cfg := &config{}
	cfg.FlagSet = flag.NewFlagSet("", flag.ContinueOnError)
	cfg.FlagSet.StringVar(&cfg.Profile, "profile", defaultProfile, "the credential profile to use")
	f(cfg.FlagSet)

	if err := cfg.FlagSet.Parse(args); err != nil {
		return cfg, err
	}

	return cfg, nil
}

func init() {
	if p := os.Getenv("AWS_DEFAULT_PROFILE"); p != "" {
		defaultProfile = p
	}
}
