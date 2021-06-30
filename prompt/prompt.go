package prompt

import (
	"fmt"
	"regexp"
	"sort"
)

type PromptFunc func(string) (string, error)

var Methods = map[string]PromptFunc{}

func Available() []string {
	methods := []string{}
	for k := range Methods {
		methods = append(methods, k)
	}
	sort.Strings(methods)
	return methods
}

func Method(s string) PromptFunc {
	m, ok := Methods[s]
	if !ok {
		panic(fmt.Sprintf("Prompt method %q doesn't exist", s))
	}
	return m
}

// names supported AWS MFA serial names
// see https://docs.aws.amazon.com/cli/latest/reference/iam/create-virtual-mfa-device.html#options
// --virtual-mfa-device-name for restrictions
var isValidMfaSerial = regexp.MustCompile(`^[a-zA-Z0-9+=/:,.+]+$`).MatchString

func validateMfaName(mfaSerial string) bool {
	return isValidMfaSerial(mfaSerial)
}

func mfaPromptMessage(mfaSerial string) string {
	return fmt.Sprintf("Enter token for %s: ", mfaSerial)
}
