package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/bgentry/speakeasy"
)

func prompt(prompt string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(prompt)
	text, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(text), nil
}

func promptPassword(prompt string) (string, error) {
	return speakeasy.Ask(prompt)
}
