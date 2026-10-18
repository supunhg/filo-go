.PHONY: build install test race cover lint fmt snapshot release clean help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)
PKG     := github.com/supunhg/filo-go/internal/version
LDFLAGS := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT)

build: ## Build ./filo
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o filo ./cmd/filo

install: ## Install filo into $GOBIN
	CGO_ENABLED=0 go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/filo

test: ## Run the test suite
	go test ./...

race: ## Run tests with the race detector
	go test -race ./...

cover: ## Write an HTML coverage report to coverage.html
	go test -covermode=atomic -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

lint: ## Run golangci-lint
	golangci-lint run

fmt: ## Format code
	golangci-lint fmt

snapshot: ## Build all release artifacts locally into dist/
	goreleaser release --snapshot --clean

release: ## Publish a release (CI does this on tag push)
	goreleaser release --clean

clean: ## Remove build output
	rm -rf filo filo.exe dist/ coverage.out coverage.html

help: ## Show this help
	@grep -E '^[a-z]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-10s %s\n", $$1, $$2}'
