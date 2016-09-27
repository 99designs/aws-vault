BIN=aws-vault
OS=$(shell uname -s)
ARCH=$(shell uname -m)
GOVERSION=$(shell go version)
GOBIN=$(shell go env GOBIN)
VERSION=$(shell git describe --tags --candidates=1 --dirty)
FLAGS=-X main.Version=$(VERSION) -s -w
CERT="Developer ID Application: 99designs Inc (NRM9HVJ62Z)"
SRC=$(shell find . -name '*.go')

test:
	go test $(shell go list ./... | grep -v /vendor/)

build:
	go build -o aws-vault -ldflags="$(FLAGS)" .

sign:
	codesign -s $(CERT) ./aws-vault

$(BIN)-linux-amd64: $(SRC)
	GOOS=linux GOARCH=amd64 go build -o $@ -ldflags="$(FLAGS)" .

$(BIN)-darwin-amd64: $(SRC)
	GOOS=darwin GOARCH=amd64 go build -o $@ -ldflags="$(FLAGS)" .

$(BIN)-windows-386: $(SRC)
	GOOS=windows GOARCH=386 go build -o $@ -ldflags="$(FLAGS)" .

release: $(BIN)-linux-amd64 $(BIN)-darwin-amd64 $(BIN)-windows-386
	codesign -s $(CERT) $(BIN)-darwin-amd64

clean:
	rm -f $(BIN)-*-*
