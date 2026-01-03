# japikey_go Development Guidelines

## Active Technologies

- Go 1.25.5
- Go standard library (crypto/rand, crypto/rsa, encoding/base64, encoding/json)
- github.com/golang-jwt/jwt/v5 for JWT creation and verification
- github.com/google/uuid for UUID handling

## Project Structure

```
japikey/         - Main package for signing and verification
  sign.go        - API key signing functionality
  verify.go      - API key verification functionality
internal/jwks/   - JWKS (JSON Web Key Set) implementation
  jwks.go        - JWK to JWKS conversion
errors/          - Custom error types
  errors.go      - ValidationError, ConversionError, KeyNotFoundError, InternalError, TokenExpiredError
example/         - Example usage code
jwx/tool/        - JWKS parsing and generation tool
```

## Commands

### Build
- `make build` - Build the project
- `make build-jwx` - Build the JWKS verification tool

### Test
- `make test` - Run all tests (including examples)
- `make test-with-jwx` - Run all tests including jwx tool tests
- `make test-coverage` - Run tests with coverage report (generates coverage.html)
- `go test -v ./...` - Run tests with verbose output
- `go test -v -run TestName ./path/to/package` - Run a specific test
- `go test -v -run TestName ./japikey` - Run specific test in japikey package

### Lint and Format
- `make lint` - Run golangci-lint on all packages
- `make fmt` - Format code with gofmt (simplify and write)
- `make vet` - Run go vet for static analysis
- `make check` - Run all checks (fmt, vet, lint, test)
- `make ci` - Run all checks for CI (includes tidy, fmt, vet, lint, test, build)

### Other
- `make tidy` - Tidy go modules
- `make deps` - Install dependencies
- `make examples` - Run example programs
- `make security` - Run security scan with govulncheck

## Code Style

### General
- Follow standard Go conventions and idioms
- Use `gofmt -s -w .` for formatting
- Run `make check` before committing
- Ensure all tests pass before submitting PRs

### Imports
- Group imports in order: standard library, third-party, internal
- Separate groups with blank lines
- Use alias for package name conflicts (e.g., `japikeyerrors "github.com/susu-dot-dev/japikey/errors"`)

### Naming Conventions
- Public functions/types: PascalCase (NewJAPIKey, Verify, Config, JAPIKey)
- Private functions/types: camelCase (validateConfig, extractKeyIDFromHeader)
- Constants: PascalCase (AlgorithmRS256, MaxTokenSize, VersionClaim)
- Interface names: usually -er suffix (JWKCallback)

### Types
- Use named types for clarity (uuid.UUID, *rsa.PublicKey)
- Use pointer types for large structs and when nil is meaningful
- Define custom error types via struct composition (errors package)

### Error Handling
- Always check and handle errors
- Use custom error types from errors package:
  - ValidationError - input validation failures
  - ConversionError - data conversion issues
  - KeyNotFoundError - missing cryptographic keys
  - InternalError - internal system errors
  - TokenExpiredError - expired tokens
- Use type assertions for specific error handling: `if _, ok := err.(*errors.ValidationError); ok`
- Return early on errors to reduce nesting

### Documentation
- Exported functions must have comments explaining purpose and behavior
- Add comments for complex logic or non-obvious code
- Include parameter and return value descriptions

### Testing
- Use table-driven tests when appropriate
- Test both success and error paths
- Arrange-Act-Assert pattern for clarity
- Use `t.Fatal` for setup failures, `t.Error` for assertion failures
- Test concurrency when applicable
- Include integration tests for full workflows

### Security
- Never expose private keys in return values
- Validate all inputs thoroughly
- Use constant-time comparisons for sensitive data
- Map generic errors to generic messages to prevent information leakage
- Enforce maximum token size limits before parsing

## Recent Changes

- 005-jwks-endpoint: Added Go 1.21+ + Go standard library (net/http, context), existing jwks package in internal/jwks/

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
