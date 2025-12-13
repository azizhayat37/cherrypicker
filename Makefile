# Makefile for CherryPicker

# Build variables
BINARY_NAME=cherrypicker
GO=go
GOFLAGS=-ldflags="-s -w"

# Platforms
PLATFORMS=linux/amd64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all clean deps build test linux windows darwin

all: deps build

# Install dependencies
deps:
	$(GO) get golang.org/x/net/icmp
	$(GO) get golang.org/x/net/ipv4
	$(GO) mod tidy

# Build for current platform
build:
	$(GO) build $(GOFLAGS) -o $(BINARY_NAME)

# Build for all platforms
build-all: linux windows darwin

# Build for Linux
linux:
	GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -o build/$(BINARY_NAME)-linux-amd64

# Build for Windows
windows:
	GOOS=windows GOARCH=amd64 $(GO) build $(GOFLAGS) -o build/$(BINARY_NAME)-windows-amd64.exe

# Build for macOS
darwin:
	GOOS=darwin GOARCH=amd64 $(GO) build $(GOFLAGS) -o build/$(BINARY_NAME)-darwin-amd64
	GOOS=darwin GOARCH=arm64 $(GO) build $(GOFLAGS) -o build/$(BINARY_NAME)-darwin-arm64

# Run tests
test:
	$(GO) test -v ./...

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -rf build/

# Show configuration
show-config:
	@echo "Building $(BINARY_NAME)"
	@echo "Go version: $$($(GO) version)"
	@echo "GOOS: $$($(GO) env GOOS)"
	@echo "GOARCH: $$($(GO) env GOARCH)"
