.PHONY: build lint test clean docker-test

BINARY_DIR := bin
GO         := go
GOFLAGS    := CGO_ENABLED=0

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -X main.version=$(VERSION) \
           -X main.commit=$(COMMIT) \
           -X main.buildDate=$(BUILD_DATE)

build:
	$(GOFLAGS) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/ezyshield ./cmd/ezyshield
	$(GOFLAGS) $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY_DIR)/ezyshield-enforcer ./cmd/ezyshield-enforcer

lint:
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	golangci-lint run ./...

test:
	$(GO) test -race -coverprofile=coverage.out -covermode=atomic ./...

clean:
	rm -rf $(BINARY_DIR) coverage.out

# Roda lint + test dentro de um container (não precisa de ferramentas instaladas no host)
docker-test:
	docker run --rm -v "$(PWD)":/app -w /app \
		golangci/golangci-lint:latest \
		sh -c "gofmt -l . && go vet ./... && golangci-lint run ./... && CGO_ENABLED=1 go test -race ./..."
