# Implementation Plan: [FEATURE]

**Branch**: `[###-feature-name]` | **Date**: [DATE] | **Spec**: [link]
**Input**: Feature specification from `/specs/[###-feature-name]/spec.md`

**Note**: This template is filled in by the `/speckit.plan` command. See `.specify/templates/commands/plan.md` for the execution workflow.

## Summary

This feature implements JWK (JSON Web Key) conversion support for JAPIKeys, allowing conversion between JAPIKey structures and JWKS (JSON Web Key Sets) format. The implementation will provide functions to generate JWKS from RSA public keys and key IDs, serialize/deserialize JWKS to/from JSON format, and extract public keys and key IDs from existing JWKS. The implementation will use Go's built-in crypto libraries to ensure RFC 7517/7518 compliance, with a jwx CLI tool using lestrrat-go/jwx/jwk to validate the output format. The solution will include proper error handling with structured errors and comprehensive validation of inputs and outputs.

The implementation follows an architecture where all JWKS-related code (except the external wrapper in japikey.go) is located in an internal/ subdirectory with a separate jwks package. The structs use lowercase variable names to enforce encapsulation and immutability after construction. Validation occurs only at construction or unmarshalling time, not on every function call. All JWKS functionality is consolidated in a single jwks.go file without a separate validation.go file.

## Technical Context

**Language/Version**: Go 1.21 or later (as specified in functional requirement FR-008)
**Primary Dependencies**: Standard Go modules (crypto/rsa, crypto/x509, encoding/base64, math/big), github.com/golang-jwt/jwt/v5 for JWT handling, golang.org/x/crypto for cryptographic operations, github.com/google/uuid for UUID handling, github.com/lestrrat-go/jwx/jwk for jwx CLI tool
**Storage**: N/A (in-memory operations, no persistent storage required)
**Testing**: Go testing package (go test), with additional verification using lestrrat-go/jwx/jwk in jwx CLI tool
**Target Platform**: Linux server, cross-platform compatibility
**Project Type**: Single library project with jwx CLI tool
**Performance Goals**: <100ms for JWKS conversion and extraction operations (95th percentile)
**Constraints**: Must use built-in Go libraries for core implementation, avoid external dependencies in main code, maintain RFC 7517/7518 compliance, consolidate all JWKS functionality in a single jwks.go file without separate validation.go file
**Scale/Scope**: Support for standard RSA key sizes (2048, 4096 bits), UUID key identifiers
**Immutability Requirements**: Struct variables must be treated as immutable after construction, with validation occurring only at construction or unmarshalling time, not on every function call
**Package Structure**: JWKS-related code (except external wrapper in japikey.go) must be located in internal/ subdirectory with separate jwks package, using lowercase variable names to enforce encapsulation
**Error Handling Requirements**: Must define and use specific error types: InvalidJWK for all errors when unmarshaling JSON files (besides standard JSON format errors), UnexpectedConversionError when converting JAPIKey to JWK fails, and KeyNotFoundError when kid is not present in the JWK
**UUID Validation Requirements**: Must use UUID data type internally instead of string to enforce that the string, if present, is a UUID
**Verification Tool Requirements**: Must provide a jwx CLI tool with parse and generate commands for verification against the lestrrat-go/jwx/jwk library, with integration into the Makefile and unit tests

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

**Library-First Architecture**: This feature is implemented as a standalone library with clear interfaces for JWKS conversion, validation, and extraction. The library is self-contained with independently testable functions and documented APIs, with no organizational-only components. The implementation is in the internal/jwks package with lowercase field names to enforce immutability after construction, and a jwx CLI tool that has its own go module to avoid external dependencies in the main code.

**Developer Ease of Use**: Implementation includes comprehensive documentation with quickstart guides, clear API examples for every behavior (NewJWKS function, serialization/deserialization, key extraction), and usage examples for common scenarios. The quickstart.md file provides clear examples for all user stories, including specific error handling examples for the new error types.

**Security-First Testing**: Security-focused tests are planned for all core features, including validation of key formats, proper encoding/decoding of cryptographic parameters, and verification that only valid JWKS structures are accepted. Tests cover both security posture and functional correctness, with verification against established libraries using the jwx CLI tool. Tests specifically validate the new error types: InvalidJWK, UnexpectedConversionError, and KeyNotFoundError.

**Specification-Driven Development**: Tests are written to validate the specification before implementation begins, ensuring that RFC 7517/7518 compliance is verified and all functional requirements are met. The implementation follows the detailed functional requirements from the specification, with validation occurring only at construction or unmarshalling time rather than on every function call. The specification explicitly defines the new error types and UUID validation requirements.

**Security & Observability**: Security-related events such as invalid JWKS inputs or failed validation attempts are logged with appropriate detail for audit trails, while ensuring that sensitive cryptographic material is not logged. The structured error handling follows the same pattern as the 002 spec, with specific error types for different failure scenarios (InvalidJWK, UnexpectedConversionError, KeyNotFoundError). The UUID data type internally enforces proper UUID format, reducing security risks from malformed identifiers. The jwx CLI tool provides an additional layer of security validation by cross-checking our implementation against the established jwx library.

## Project Structure

### Documentation (this feature)

```text
specs/003-jwk-conversion/
├── plan.md              # This file (/speckit.plan command output)
├── research.md          # Phase 0 output (/speckit.plan command)
├── data-model.md        # Phase 1 output (/speckit.plan command)
├── quickstart.md        # Phase 1 output (/speckit.plan command)
├── contracts/           # Phase 1 output (/speckit.plan command)
└── tasks.md             # Phase 2 output (/speckit.tasks command - NOT created by /speckit.plan)
```

### Source Code (repository root)

```text
japikey/
├── jwks.go               # Main JWKS implementation with NewJWKS function, serialization methods
├── jwks_test.go          # Unit tests for JWKS functionality
├── errors.go             # Structured error types following 002 spec pattern
└── japikey.go            # External wrapper for JAPIKey functionality

internal/
└── jwks/
    ├── jwks.go           # JWKS implementation with lowercase field names, immutable structs
    ├── jwks_test.go      # Unit tests for JWKS functionality
    └── errors.go         # Internal error types for the jwks package

jwx/
└── tool/
    ├── main.go           # Main jwx CLI tool entry point with parse and generate commands
    ├── parse.go          # Parse command implementation for JWK to base64 public key
    ├── generate.go       # Generate command implementation for base64 public key to JWK
    ├── go.mod            # Separate go module for jwx CLI tool using lestrrat-go/jwx/jwk
    └── go.sum

example/
├── jwks_example.go       # Example usage of JWKS functionality
└── jwks.json             # Generated JWKS test file

tests/
└── verification/
    └── jwks_test.json    # Verification test data generated by script

Makefile                  # Contains command to build jwx CLI tool
```

**Structure Decision**: This feature follows the single project structure with a library-first approach. The main JWKS implementation is in the internal/jwks package with lowercase field names to enforce immutability. The external japikey package provides a wrapper for JAPIKey functionality. The jwx CLI tool is in a separate jwx/tool module that uses the lestrrat-go/jwx/jwk library to provide an independent verification oracle. The generated JWKS test data is stored in example/jwks.json and tests/verification/jwks_test.json.

## Complexity Tracking

> **Fill ONLY if Constitution Check has violations that must be justified**

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| [e.g., 4th project] | [current need] | [why 3 projects insufficient] |
| [e.g., Repository pattern] | [specific problem] | [why direct DB access insufficient] |
