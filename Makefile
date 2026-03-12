.PHONY := help test-min test-all build-linux build-windows build-darwin build-tools build-all

# Default minimal test packages that run safely in sandboxes
PKG_MIN := ./fakeca ./ietf-cms/timestamp

# Default to using Go fallback roots unless overridden by the environment
GODEBUG ?= x509usefallbackroots=1
BUILD_DIR ?= build
GIT_VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null)
LDFLAGS ?= -X main.versionString=$(GIT_VERSION)
WINDOWS_CC_AMD64 ?= x86_64-w64-mingw32-gcc
WINDOWS_CC_386 ?= i686-w64-mingw32-gcc
DARWIN_CC_AMD64 ?= o64-clang
DARWIN_CC_ARM64 ?= oa64-clang

define require-tool
	@command -v $(1) >/dev/null 2>&1 || { \
		echo "Missing required tool: $(1)"; \
		echo "$(2)"; \
		exit 1; \
	}
endef

help:
	@echo "Targets:"
	@echo "  test-min  - Run a minimal, sandbox-safe subset of tests"
	@echo "  test-all  - Run all tests (may require macOS keychain access)"
	@echo "  build-tools - Build helper tools such as git-x509-cert"
	@echo ""
	@echo "Environment:"
	@echo "  GODEBUG   - Defaults to 'x509usefallbackroots=1' to avoid system truststore access issues"
	@echo "  WINDOWS_CC_AMD64 / WINDOWS_CC_386 - Windows cgo cross-compilers"
	@echo "  DARWIN_CC_AMD64 / DARWIN_CC_ARM64 - macOS cgo cross-compilers"

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
	$(call require-tool,$(WINDOWS_CC_AMD64),Install a MinGW-w64 cross-compiler or override WINDOWS_CC_AMD64.)
	$(call require-tool,$(WINDOWS_CC_386),Install a MinGW-w64 i686 cross-compiler or override WINDOWS_CC_386.)
	@echo "[build-windows] GOOS=windows GOARCH=amd64"
	CC=$(WINDOWS_CC_AMD64) CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -o $(BUILD_DIR)/windows/amd64/smimesign.exe -ldflags "$(LDFLAGS)" .
	@echo "[build-windows] GOOS=windows GOARCH=386"
	CC=$(WINDOWS_CC_386) CGO_ENABLED=1 GOOS=windows GOARCH=386 go build -o $(BUILD_DIR)/windows/386/smimesign.exe -ldflags "$(LDFLAGS)" .

build-darwin:
	$(call require-tool,$(DARWIN_CC_AMD64),Install osxcross / an Apple-targeting SDK toolchain or override DARWIN_CC_AMD64.)
	$(call require-tool,$(DARWIN_CC_ARM64),Install osxcross / an Apple-targeting SDK toolchain or override DARWIN_CC_ARM64.)
	@echo "[build-darwin] GOOS=darwin GOARCH=amd64"
	CC=$(DARWIN_CC_AMD64) CGO_ENABLED=1 GOOS=darwin GOARCH=amd64 go build -o $(BUILD_DIR)/darwin/amd64/smimesign -ldflags "$(LDFLAGS)" .
	@echo "[build-darwin] GOOS=darwin GOARCH=arm64"
	CC=$(DARWIN_CC_ARM64) CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 go build -o $(BUILD_DIR)/darwin/arm64/smimesign -ldflags "$(LDFLAGS)" .

build-tools:
	@echo "[build-tools] Building git-x509-cert"
	go build -o $(BUILD_DIR)/tools/git-x509-cert ./cmd/git-x509-cert

build-all: build-linux build-windows build-darwin build-tools
