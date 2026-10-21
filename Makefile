BINARY_NAME=mcp-jail
BIN_DIR=bin
GO=go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.2.0")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS ?= -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: all build test test-coverage lint clean install

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/mcp-jail

test:
	$(GO) test -v -timeout 30s ./...

test-coverage:
	$(GO) test -v -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out

lint:
	$(GO) vet ./...
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed, skipped extended linting"; \
	fi

clean:
	rm -rf $(BIN_DIR)
	rm -f coverage.out
	rm -f *.db *.db-journal *.db-wal *.db-shm

install:
	CGO_ENABLED=0 $(GO) install -trimpath -ldflags="$(LDFLAGS)" ./cmd/mcp-jail

docs-serve:
	@echo "Serving documentation at http://localhost:8000 ..."
	python3 -m http.server 8000 --directory docs

docs-update:
	gh release download --repo smford/md-web-renderer --pattern "index.html" --dir docs --clobber || \
	curl -sSL https://github.com/smford/md-web-renderer/releases/latest/download/index.html -o docs/index.html
	touch docs/.nojekyll
