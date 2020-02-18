VERSION=$(shell git describe --tags --candidates=1 --dirty)
BUILD_FLAGS=-ldflags="-X main.Version=$(VERSION) -s -w" -trimpath
CERT_ID ?= Developer ID Application: 99designs Inc (NRM9HVJ62Z)
SRC=$(shell find . -name '*.go')

export CGO_ENABLED=0

.PHONY: binaries clean release install

binaries: aws-vault-linux-amd64 aws-vault-linux-arm64 aws-vault-darwin-amd64 aws-vault-windows-386.exe aws-vault-freebsd-amd64

clean:
	rm -f aws-vault aws-vault-linux-amd64 aws-vault-linux-arm64 aws-vault-darwin-amd64 aws-vault-darwin-amd64.dmg aws-vault-windows-386.exe aws-vault-freebsd-amd64 SHA256SUMS

release: binaries aws-vault-darwin-amd64.dmg SHA256SUMS
	@echo "\nTo update homebrew-cask run\n\n    cask-repair -v $(shell echo $(VERSION) | sed 's/v\(.*\)/\1/') aws-vault\n"

aws-vault-darwin-amd64: $(SRC)
	GOOS=darwin GOARCH=amd64 go build $(BUILD_FLAGS) -o $@ .

aws-vault-freebsd-amd64: $(SRC)
	GOOS=freebsd GOARCH=amd64 go build $(BUILD_FLAGS) -o $@ .

aws-vault-linux-amd64: $(SRC)
	GOOS=linux GOARCH=amd64 go build $(BUILD_FLAGS) -o $@ .

aws-vault-linux-arm64: $(SRC)
	GOOS=linux GOARCH=arm64 go build $(BUILD_FLAGS) -o $@ .

aws-vault-windows-386.exe: $(SRC)
	GOOS=windows GOARCH=386 go build $(BUILD_FLAGS) -o $@ .

aws-vault-darwin-amd64.dmg: aws-vault-darwin-amd64
	./bin/create-dmg aws-vault-darwin-amd64 $@

SHA256SUMS: binaries aws-vault-darwin-amd64.dmg
	shasum -a 256 aws-vault-freebsd-amd64 aws-vault-linux-amd64 aws-vault-linux-arm64 aws-vault-windows-386.exe aws-vault-darwin-amd64.dmg > $@

install:
	rm -f aws-vault
	go build $(BUILD_FLAGS) .
	codesign --options runtime --timestamp --sign "$(CERT_ID)" aws-vault
	mv aws-vault ~/bin/
