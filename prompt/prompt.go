package prompt

import (
	"errors"
	"fmt"
)

type PromptFunc func(string) (string, error)

var Methods = map[string]PromptFunc{
	"terminal": TerminalPrompt,
}

var errPromptAborted = errors.New("User cancelled prompt with no value")

func Available() []string {
	methods := []string{}
	for k := range Methods {
		methods = append(methods, k)
	}
	return methods
}

func Method(s string) PromptFunc {
	m, ok := Methods[s]
	if !ok {
		panic(fmt.Sprintf("Prompt method %q doesn't exist", s))
	}
	return m
}
