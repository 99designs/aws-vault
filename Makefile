VERSION := $(shell git describe --tags --candidates=1 --dirty)
GOBUILD_ARGS := -ldflags "-s -X main.Version=$(VERSION)"
OS := $(shell uname -s)
ARCH := $(shell uname -m)
BIN := aws-vault
SIGN_IDENTITY := "3rd Party Mac Developer Application: 99designs Inc (NRM9HVJ62Z)"

.PHONY: build install sign clean

$(BIN):
	godep go build $(GOBUILD_ARGS) -o $(BIN) .

clean:
	-rm $(BIN)
	-rm $(BIN)-$(OS)-$(ARCH)

build: $(BIN)

install: $(BIN)
	cp $(BIN) $(GOBIN)/$(BIN)

sign: build
	codesign -s $(SIGN_IDENTITY) -v $(BIN)

release: sign
	cp $(BIN) $(BIN)-$(OS)-$(ARCH)
	@echo Upload $(BIN)-$(OS)-$(ARCH) as $(VERSION)