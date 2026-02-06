.PHONY := help test-min test-all build-linux build-windows build-darwin build-all

# Default minimal test packages that run safely in sandboxes
PKG_MIN := ./fakeca ./ietf-cms/timestamp

# Default to using Go fallback roots unless overridden by the environment
GODEBUG ?= x509usefallbackroots=1
BUILD_DIR ?= build
GIT_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
LDFLAGS ?= -X main.versionString=$(GIT_VERSION)

help:
	@echo "Targets:"
	@echo "  test-min  - Run a minimal, sandbox-safe subset of tests"
	@echo "  test-all  - Run all tests (may require macOS keychain access)"
	@echo ""
	@echo "Environment:"
	@echo "  GODEBUG   - Defaults to 'x509usefallbackroots=1' to avoid system truststore access issues"

test-min:
	@echo "[test-min] Running: $(PKG_MIN)"
	GODEBUG=$(GODEBUG) go test -v $(PKG_MIN)

test-all:
	@echo "[test-all] Running: ./... (some tests may require unsandboxed macOS keychain access)"
	GODEBUG=$(GODEBUG) go test -v ./...

build-linux:
	@echo "[build-linux] GOOS=linux GOARCH=amd64"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o $(BUILD_DIR)/linux/amd64/smimesign -ldflags "$(LDFLAGS)" .
	@echo "[build-linux] GOOS=linux GOARCH=386"
	CGO_ENABLED=0 GOOS=linux GOARCH=386 go build -o $(BUILD_DIR)/linux/386/smimesign -ldflags "$(LDFLAGS)" .

build-windows:
	@echo "[build-windows] GOOS=windows GOARCH=amd64"
	CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/windows/amd64/smimesign.exe -ldflags "$(LDFLAGS)" .
	@echo "[build-windows] GOOS=windows GOARCH=386"
	CGO_ENABLED=1 GOOS=windows GOARCH=386 go build -o $(BUILD_DIR)/windows/386/smimesign.exe -ldflags "$(LDFLAGS)" .

build-darwin:
	@echo "[build-darwin] GOOS=darwin GOARCH=amd64"
	CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/darwin/amd64/smimesign -ldflags "$(LDFLAGS)" .
	@echo "[build-darwin] GOOS=darwin GOARCH=arm64"
	CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/darwin/arm64/smimesign -ldflags "$(LDFLAGS)" .

build-all: build-linux build-windows build-darwin

