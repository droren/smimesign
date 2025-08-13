.PHONY := help test-min test-all

# Default minimal test packages that run safely in sandboxes
PKG_MIN := ./fakeca ./ietf-cms/timestamp

# Default to using Go fallback roots unless overridden by the environment
GODEBUG ?= x509usefallbackroots=1

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

