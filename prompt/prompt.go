package prompt

import (
	"fmt"
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

func mfaPromptMessage(mfaSerial string) string {
	return fmt.Sprintf("Enter token for %s: ", mfaSerial)
}
