VERSION := $(shell git describe --tags --candidates=1)
GOBUILD_ARGS := -ldflags "-s -X main.Version=$(VERSION)"
OS := $(shell uname -s)
ARCH := $(shell uname -m)
BIN := aws-vault
FULL_BIN := $(BIN)-$(OS)-$(ARCH)
SIGN_IDENTITY := "3rd Party Mac Developer Application: 99designs Inc (NRM9HVJ62Z)"

.PHONY: build install sign clean

$(FULL_BIN):
	godep go build $(GOBUILD_ARGS) -o $(FULL_BIN) .

clean:
	-rm $(FULL_BIN)

build: $(FULL_BIN)

install: $(FULL_BIN)
	cp $(FULL_BIN) $(GOBIN)/$(BIN)

sign: build
	codesign -s $(SIGN_IDENTITY) -v $(FULL_BIN)