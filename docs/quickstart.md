# Quickstart Guide

## Installation

To use japikey-go in your project, simply add it as a Go module:

```bash
go mod init your-project
go get github.com/susu-dot-dev/japikey-go
```

## Local Development

For local development, we provide a Makefile with common commands:

```bash
# Run tests
make test

# Format code
make fmt

# Run linting
make lint

# Run all checks (format, vet, lint, test)
make check

# Build the project
make build

# Run all checks and build (for CI)
make ci
```

## Basic Usage

Here's a minimal example to get started with japikey-go:

```go
package main

import (
    "fmt"
    "github.com/susu-dot-dev/japikey-go/hello"
)

func main() {
    result := hello.GetMessage()
    fmt.Println(result) // Outputs: Hello, World!
}
```

## Requirements

- Go 1.21 or later
- Linux or Mac operating system

## Next Steps

Check out the hello module in the `hello/` directory for a complete example of basic functionality.