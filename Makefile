.PHONY: build test lint clean install

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o filo ./cmd/filo/

test:
	go test -v ./...

lint:
	golangci-lint run

clean:
	rm -f filo
	rm -rf dist/

install:
	go install $(LDFLAGS) ./cmd/filo/

dev:
	go run ./cmd/filo/

release:
	goreleaser release --clean

snapshot:
	goreleaser release --snapshot --clean
