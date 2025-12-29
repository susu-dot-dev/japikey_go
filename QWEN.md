# japikey_go Development Guidelines

Auto-generated from all feature plans. Last updated: 2025-12-29

## Core Principles (from Constitution)

1. **Library-First Architecture**: Every feature starts as a standalone library; Libraries must be self-contained, independently testable, documented; Clear purpose required - no organizational-only libraries
2. **Developer Ease of Use**: Usage MUST be documented in a way that encourages easy developer absorption of the library. This includes easy to understand APIs, quickstart and usage examples for every behavior
3. **Security-First Testing**: All core features must be fully tested for correctness from a security posture as well as a functional perspective
4. **Specification-Driven Development**: Tests must be written to validate the correctness of the spec before implementing the features. This ensures that the spec is accurately capturing the behavior, and remains up to date
5. **Security & Observability**: Security-focused logging and monitoring; All security-related events must be logged with appropriate detail for audit trails

## Active Technologies
- Files only (for documentation and configuration) (001-dev-experience)

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
- 001-dev-experience: Added Go 1.21 or later (as specified in functional requirement FR-008) + Standard Go modules, github.com/golang-jwt/jwt/v5 for JWT handling, golang.org/x/crypto for cryptographic operations

- 001-dev-experience: Added Go 1.21 or later (as specified in functional requirement FR-008) + Standard Go modules, github.com/golang-jwt/jwt/v5 for JWT handling, golang.org/x/crypto for cryptographic operations

<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
