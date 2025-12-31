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
	$(GOBUILD) -v ./...

## Run tests
.PHONY: test
test:
	$(GOTEST) -v ./...
	@echo "Running example to ensure it works..."
	cd example && go run main.go

## Run examples
.PHONY: examples
examples:
	@echo "Running example to ensure it works..."
	cd example && go run main.go

## Run tests with coverage
.PHONY: test-coverage
test-coverage:
	$(GOTEST) -v -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## Run linting
.PHONY: lint
lint:
	golangci-lint run ./...
	
## Format code
.PHONY: fmt
fmt:
	$(GOFMT) -s -w .

## Vet code
.PHONY: vet
vet:
	$(GOVET) ./...

## Tidy go modules
.PHONY: tidy
tidy:
	$(GOMOD) tidy

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
	$(GOGET) -t -v ./...

## Run security scan
.PHONY: security
security:
	$(GOCMD) run golang.org/x/vuln/cmd/govulncheck@latest ./...

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
	@echo "  test          - Run tests"
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
