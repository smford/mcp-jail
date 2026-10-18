BINARY_NAME=mcp-jail
BIN_DIR=bin
GO=go

.PHONY: all build test test-coverage lint clean install

all: build

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/$(BINARY_NAME) ./cmd/mcp-jail

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
	CGO_ENABLED=0 $(GO) install -trimpath -ldflags="-s -w" ./cmd/mcp-jail
