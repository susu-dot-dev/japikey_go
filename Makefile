# Makefile for japikey-go
#
# This Makefile provides commands for building, testing, and linting the japikey-go project.
# It is designed to work consistently in both local development and CI environments.

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOTIDY=$(GOCMD) tidy
GOLIST=$(GOCMD) list
GOVET=$(GOCMD) vet
GOFMT=gofmt
GOLINT=golangci-lint

# Modules in the go.work workspace. "./..." only matches the module in the
# current directory, so targets that need to cover everything loop over these.
MODULES=. example integration jwx/tool

# Binary name
BINARY_NAME=japikey-go

# Build directory
BUILD_DIR=build

# Default target
.PHONY: all
all: test

## Build the project
.PHONY: build
build:
	@for m in $(MODULES); do (cd $$m && $(GOBUILD) -v ./...) || exit 1; done

## Build the jwx verification tool
.PHONY: build-jwx
build-jwx:
	cd jwx/tool && $(GOBUILD) -v ./...

## Run the jwx verification tool
.PHONY: run-jwx
run-jwx: build-jwx
	@echo "Running jwx tool..."
	@cd jwx/tool && go run . --help

## Run tests
.PHONY: test
test: build-jwx
	@for m in $(MODULES); do (cd $$m && $(GOTEST) -v ./...) || exit 1; done
	@$(MAKE) --no-print-directory examples

## Run tests including jwx tool (kept for compatibility; test already covers it)
.PHONY: test-with-jwx
test-with-jwx: test

## Run examples
.PHONY: examples
examples:
	@echo "Running examples to ensure they work..."
	cd example && go run ./basic
	cd example && go run ./jwks

## Run tests with coverage
.PHONY: test-coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## Run linting
.PHONY: lint
lint:
	@for m in $(MODULES); do (cd $$m && $(GOLINT) run ./...) || exit 1; done

## Format code
.PHONY: fmt
fmt:
	$(GOFMT) -s -w .

## Vet code
.PHONY: vet
vet:
	@for m in $(MODULES); do (cd $$m && $(GOVET) ./...) || exit 1; done

## Tidy go modules
.PHONY: tidy
tidy:
	@for m in $(MODULES); do (cd $$m && $(GOMOD) tidy) || exit 1; done

## Clean build artifacts
.PHONY: clean
clean:
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)

## Run all checks (lint, test, vet)
.PHONY: check
check: fmt vet lint test

## Install dependencies
.PHONY: deps
deps:
	@for m in $(MODULES); do (cd $$m && $(GOGET) -t -v ./...) || exit 1; done

## Run security scan
.PHONY: security
security:
	@for m in $(MODULES); do (cd $$m && $(GOCMD) run golang.org/x/vuln/cmd/govulncheck@latest ./...) || exit 1; done

## Generate documentation
.PHONY: docs
docs:
	$(GOCMD) doc -all .

## Run all checks and build
.PHONY: ci
ci: deps tidy fmt vet lint test build

# Help target
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build         - Build the project"
	@echo "  build-jwx     - Build the jwx verification tool"
	@echo "  test          - Run tests"
	@echo "  test-with-jwx - Alias for test (which already covers the jwx tool)"
	@echo "  examples      - Run examples"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  vet           - Vet code"
	@echo "  tidy          - Tidy go modules"
	@echo "  clean         - Clean build artifacts"
	@echo "  check         - Run all checks (fmt, vet, lint, test)"
	@echo "  deps          - Install dependencies"
	@echo "  security      - Run security scan"
	@echo "  docs          - Generate documentation"
	@echo "  ci            - Run all checks and build (for CI)"
	@echo "  help          - Show this help"
