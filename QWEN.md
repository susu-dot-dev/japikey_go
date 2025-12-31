# japikey_go Development Guidelines

Auto-generated from all feature plans. Last updated: 2025-12-29

## Core Principles (from Constitution)

1. **Library-First Architecture**: Every feature starts as a standalone library; Libraries must be self-contained, independently testable, documented; Clear purpose required - no organizational-only libraries
2. **Developer Ease of Use**: Usage MUST be documented in a way that encourages easy developer absorption of the library. This includes easy to understand APIs, quickstart and usage examples for every behavior
3. **Security-First Testing**: All core features must be fully tested for correctness from a security posture as well as a functional perspective
4. **Specification-Driven Development**: Tests must be written to validate the correctness of the spec before implementing the features. This ensures that the spec is accurately capturing the behavior, and remains up to date
5. **Security & Observability**: Security-focused logging and monitoring; All security-related events must be logged with appropriate detail for audit trails
6. **Code Quality Standards**: All code comments must add value that is not obvious from the code itself. Comments that merely restate the obvious, duplicate what the code clearly expresses, or describe what the code is doing step-by-step are prohibited. Function documentation should be omitted for simple functions where the name clearly indicates its purpose. Comments should focus on the "why" rather than the "what", explaining the reasoning behind complex implementations, security considerations, or non-obvious design decisions. Words describing how things work generally belong in specs, not in code comments.
7. **Testing Requirement**: A coding task is not considered complete unless it has been tested, whenever possible. This ensures code reliability and prevents regressions.

## Active Technologies
- Files only (for documentation and configuration) (001-dev-experience)
- Go 1.21 or later + github.com/golang-jwt/jwt/v5 for JWT handling, golang.org/x/crypto for cryptographic operations (002-japikey-signing)
- N/A (in-memory operations, no persistent storage required) (002-japikey-signing)
- Go 1.21 or later (as specified in functional requirement FR-008) + Standard Go modules (crypto/rsa, crypto/x509, encoding/base64, math/big), github.com/golang-jwt/jwt/v5 for JWT handling, golang.org/x/crypto for cryptographic operations (003-jwk-conversion)

- Go 1.21 or later (as specified in functional requirement FR-008) + Standard Go modules, github.com/golang-jwt/jwt/v5 for JWT handling, golang.org/x/crypto for cryptographic operations (001-dev-experience)

## Project Structure

```text
src/
tests/
```

## Commands

# Add commands for Go 1.21 or later (as specified in functional requirement FR-008)

## Code Style

Go 1.21 or later (as specified in functional requirement FR-008): Follow standard conventions

## Recent Changes
- 003-jwk-conversion: Added Go 1.21 or later (as specified in functional requirement FR-008) + Standard Go modules (crypto/rsa, crypto/x509, encoding/base64, math/big), github.com/golang-jwt/jwt/v5 for JWT handling, golang.org/x/crypto for cryptographic operations
- 003-jwk-conversion: Added Go 1.21 or later (as specified in functional requirement FR-008) + Standard Go modules (crypto/rsa, crypto/x509, encoding/base64, math/big), github.com/golang-jwt/jwt/v5 for JWT handling, golang.org/x/crypto for cryptographic operations
- 003-jwk-conversion: Added Go 1.21 or later (as specified in functional requirement FR-008) + Standard Go modules, github.com/golang-jwt/jwt/v5 for JWT handling, golang.org/x/crypto for cryptographic operations


<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
