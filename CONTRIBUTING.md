# Contributing to japikey-go

Thank you for your interest in contributing to japikey-go! This document outlines the process for contributing to this project.

## Prerequisites

- Go 1.21 or later
- Linux or Mac operating system (Windows is not supported)
- Git

## Setup

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/japikey-go.git
   cd japikey-go
   ```
3. Add the upstream repository as a remote:
   ```bash
   git remote add upstream https://github.com/susu-dot-dev/japikey-go.git
   ```

## Development Workflow

1. Create a new branch for your feature or bug fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes

3. Use the Makefile to run checks before committing:
   ```bash
   make check
   ```

4. Commit your changes with a descriptive commit message

5. Push your changes to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

6. Create a pull request to the main repository

## Development Commands

This project uses a Makefile for common development tasks:

- `make test` - Run tests
- `make lint` - Run linter
- `make fmt` - Format code
- `make vet` - Vet code for common issues
- `make check` - Run all checks (fmt, vet, lint, test)
- `make build` - Build the project
- `make ci` - Run all checks and build (for CI)

## Code Style

- Follow the Go formatting conventions (use `make fmt` to format your code)
- Write clear, descriptive comments
- Include tests for new functionality
- Follow the existing code style in the project

## Testing

All code changes must include appropriate tests. Run tests with:

```bash
make test
```

For tests with coverage:

```bash
make test-coverage
```

## Pull Request Process

1. Ensure your code follows the project's style and conventions
2. Run all checks with `make check`
3. Write a clear description of your changes in the pull request
4. Link any related issues in the pull request description
5. Wait for review and address any feedback

## Troubleshooting

### Go Version Issues
If you encounter issues with Go versions, ensure you're using Go 1.21 or later:
```bash
go version
```

### Module Issues
If you have problems with Go modules, try:
```bash
go clean -modcache
make deps
```

### Linting Issues
If the linter fails, make sure you have golangci-lint installed:
```bash
go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
```

## Questions?

If you have questions about contributing, feel free to open an issue or contact the maintainers.