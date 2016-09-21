BIN=aws-vault
OS=$(shell uname -s)
ARCH=$(shell uname -m)
PREFIX=github.com/99designs/aws-vault
GOVERSION=$(shell go version)
GOBIN=$(shell go env GOBIN)
VERSION=$(shell git describe --tags --candidates=1 --dirty)
FLAGS=-X main.Version=$(VERSION) -s -w
CERT="3rd Party Mac Developer Application: 99designs Inc (NRM9HVJ62Z)"
SRC=$(shell find . -name '*.go')

build:
	go build -o aws-vault -ldflags="$(FLAGS)" $(PREFIX)

sign:
	codesign -s $(CERT) ./aws-vault

$(BIN)-linux-amd64: $(SRC)
	GOOS=linux GOARCH=amd64 go build -o $@ -ldflags="$(FLAGS)" *.go

$(BIN)-darwin-amd64: $(SRC)
	GOOS=darwin GOARCH=amd64 go build -o $@ -ldflags="$(FLAGS)" *.go

$(BIN)-windows-386: $(SRC)
	GOOS=windows GOARCH=386 go build -o $@ -ldflags="$(FLAGS)" *.go

release: $(BIN)-linux-amd64 $(BIN)-darwin-amd64 $(BIN)-windows-386
	codesign -s $(CERT) $(BIN)-darwin-amd64
