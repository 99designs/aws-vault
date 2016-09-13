OS=$(shell uname -s)
ARCH=$(shell uname -m)
PREFIX=github.com/99designs/aws-vault
GOVERSION=$(shell go version)
GOBIN=$(shell go env GOBIN)
VERSION=$(shell git describe --tags --candidates=1 --dirty)
FLAGS=-X main.Version=$(VERSION) -s
CERT="3rd Party Mac Developer Application: 99designs Inc (NRM9HVJ62Z)"

build:
	go build -o aws-vault -ldflags="$(FLAGS)" $(PREFIX)

sign:
	codesign -s $(CERT) ./aws-vault

release: build sign
	cp aws-vault aws-vault-$(OS)-$(ARCH)
	@echo Upload aws-vault-$(OS)-$(ARCH) as $(VERSION)