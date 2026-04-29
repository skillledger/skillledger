VERSION := $(shell cat cli/VERSION 2>/dev/null || echo "dev")
MODULE := github.com/skillledger/skillledger
LDFLAGS := -ldflags "-s -w -X $(MODULE)/internal/cmd.version=$(VERSION)"
BINARY := skillledger

.PHONY: build build-all npm-build clean test

## Build the CLI binary for the current platform
build:
	cd cli && CGO_ENABLED=0 go build $(LDFLAGS) -o ../bin/$(BINARY) ./cmd/skillledger/

## Cross-compile for all 5 target platforms
build-all:
	cd cli && CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o ../bin/$(BINARY)-darwin-arm64 ./cmd/skillledger/
	cd cli && CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o ../bin/$(BINARY)-darwin-amd64 ./cmd/skillledger/
	cd cli && CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build $(LDFLAGS) -o ../bin/$(BINARY)-linux-amd64 ./cmd/skillledger/
	cd cli && CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build $(LDFLAGS) -o ../bin/$(BINARY)-linux-arm64 ./cmd/skillledger/
	cd cli && CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o ../bin/$(BINARY)-windows-amd64.exe ./cmd/skillledger/

## Generate npm platform packages from templates (requires build-all first)
npm-build: build-all
	node npm/scripts/build-packages.js

## Run Go CLI tests
test:
	cd cli && go test ./...

## Clean build artifacts
clean:
	rm -rf bin/ npm/dist/
