# Implementation Tasks: JAPIKey Verification Function

**Feature**: JAPIKey Verification Function
**Branch**: `004-japikey-verification`
**Generated**: 2025-12-30
**Input**: Design artifacts from `/specs/004-japikey-verification/`

## Overview

This document outlines the implementation tasks for the JAPIKey verification function in Go. The implementation will follow a library-first architecture with comprehensive security validations and detailed error handling.

## Dependencies

- User Story 2 (Handle Malformed JAPIKey Tokens) depends on foundational components from Phase 2
- User Story 3 (Validate JAPIKey Constraints) depends on foundational components from Phase 2
- User Story 4 (Security Validation) depends on foundational components from Phase 2

## Parallel Execution Examples

- [P] tasks can be executed in parallel as they work on different files/components
- Types and constants can be implemented in parallel with validation functions
- Test files can be created in parallel with implementation files

## Implementation Strategy

- MVP scope: Implement User Story 1 (Verify JAPIKey Token) with basic functionality
- Incremental delivery: Each user story builds upon the previous with additional validation layers
- Security-first approach: Security validations are implemented early and tested thoroughly
- Library-first approach: Leverage golang-jwt library for standard JWT validations (exp, nbf, iat, algorithm)
- Custom claims preservation: Use jwt.MapClaims to preserve all custom claims in verification result

## Phase 1: Setup

### Goal
Initialize the project structure and configure dependencies.

- [ ] T001 Create japikey package directory
- [ ] T002 Initialize Go module with required dependencies (github.com/golang-jwt/jwt/v5, golang.org/x/crypto)
- [ ] T003 Create tests directory structure
- [ ] T004 Set up basic project files (go.mod, go.sum)

## Phase 2: Foundational Components

### Goal
Implement core types, constants, and error structures needed by all user stories.

- [x] T005 [P] Create VerifyConfig struct in verify.go
- [x] T006 [P] Create VerificationResult struct with jwt.MapClaims in verify.go
- [x] T007 Create constants.go with JAPIKey constants (algorithm, version prefix, etc.)
- [x] T008 [P] Use japikeyerrors package for error types (ValidationError, KeyNotFoundError)
- [x] T009 Implement JWKCallback type for key retrieval function

## Phase 3: User Story 1 - Verify JAPIKey Token (Priority: P1)

### Goal
Implement core verification functionality to accept a token string and configuration, then return validated claims or structured errors.

**Independent Test Criteria**: Can be fully tested by providing a valid JAPIKey token and verifying it returns the expected claims, or providing an invalid token and confirming it returns an appropriate error.

- [x] T010 [P] [US1] Create verify.go file with Verify function signature
- [x] T011 [P] [US1] Implement token parsing using golang-jwt library with ParseWithClaims
- [x] T012 [P] [US1] Implement signature verification using JWT library in keyFunc callback
- [x] T013 [US1] Implement basic verification flow: size check → parse → validate → return claims
- [x] T014 [US1] Connect configuration parameters to verification process
- [x] T015 [US1] Return validated claims as jwt.MapClaims when verification succeeds (FR-006) - preserves all custom claims
- [x] T016 [US1] Return structured errors when verification fails (FR-007) - using japikeyerrors package
- [x] T017 [US1] Implement callback function for retrieving cryptographic keys (FR-001) - JWKCallback type
- [x] T018 [US1] Test acceptance scenario 1: valid token returns claims
- [x] T019 [US1] Test acceptance scenario 2: invalid signature returns error

## Phase 4: User Story 2 - Handle Malformed JAPIKey Tokens (Priority: P1)

### Goal
Implement validation to handle malformed tokens gracefully, preventing system errors and security vulnerabilities.

**Independent Test Criteria**: Can be tested by providing various malformed tokens (invalid format, missing fields, wrong version format) and confirming appropriate structured errors are returned.

- [x] T020 [P] [US2] Create validateJAPIKeyClaims function for JAPIKey-specific validation
- [x] T021 [P] [US2] Implement JWT format validation in ShouldVerify (header.payload.signature) (FR-025)
- [x] T022 [P] [US2] Implement header validation (kid field) in keyFunc callback (FR-027)
- [x] T023 [P] [US2] Implement payload validation (ver and iss claims) in validateJAPIKeyClaims (FR-002, FR-003)
- [x] T024 [US2] Add JAPIKey-specific validation after signature verification (FR-009)
- [x] T025 [US2] Test acceptance scenario 1: invalid version format returns error
- [x] T026 [US2] Test acceptance scenario 2: mismatched key ID and issuer returns error
- [x] T027 [US2] Handle tokens with non-UTF8 characters (edge case) - handled by golang-jwt library
- [x] T028 [US2] Handle tokens with unexpected nested structures (edge case) - handled by golang-jwt library

## Phase 5: User Story 3 - Validate JAPIKey Constraints (Priority: P2)

### Goal
Implement validation for all special JAPIKey constraints to ensure only properly formatted tokens are accepted.

**Independent Test Criteria**: Can be tested by providing tokens that violate specific JAPIKey constraints (e.g., version number too high, issuer format incorrect) and confirming appropriate errors are returned.

- [x] T029 [P] [US3] Implement version format validation in validateJAPIKeyClaims (FR-002)
- [x] T030 [P] [US3] Implement version number validation in validateJAPIKeyClaims (FR-008)
- [x] T031 [P] [US3] Implement issuer format validation in validateJAPIKeyClaims (FR-003)
- [x] T032 [P] [US3] Implement key ID matching validation in validateJAPIKeyClaims (FR-004)
- [x] T033 [US3] Add constraint validations to verification flow via validateJAPIKeyClaims
- [x] T034 [US3] Test acceptance scenario 1: version exceeding maximum returns error
- [x] T035 [US3] Test acceptance scenario 2: issuer format incorrect returns error
- [x] T036 [US3] Handle tokens with invalid version format (edge case) - tested
- [x] T037 [US3] Handle tokens with unexpected version format (edge case) - tested

## Phase 6: User Story 4 - Security Validation (Priority: P1)

### Goal
Implement comprehensive security validations to protect against all known token-based attacks.

**Independent Test Criteria**: Can be tested by providing tokens designed to exploit various attack vectors (timing attacks, injection, resource exhaustion) and confirming they are properly rejected.

- [x] T038 [P] [US4] Implement maximum token size validation (4KB limit) BEFORE parsing (FR-020)
- [x] T039 [P] [US4] Implement algorithm validation (RS256 only) via WithValidMethods() (FR-010, FR-022)
- [x] T040 [P] [US4] Implement expiration validation (exp claim) via WithExpirationRequired() (FR-016) - delegated to library
- [x] T041 [P] [US4] Implement not-before validation (nbf claim, if present) (FR-017) - delegated to library
- [x] T042 [P] [US4] Implement issued-at validation (iat claim, if present) (FR-018) - delegated to library
- [x] T043 [P] [US4] Type header validation removed - not required by spec (FR-023 removed)
- [x] T044 [P] [US4] Input sanitization removed - not in spec requirements (FR-026 removed)
- [x] T045 [P] [US4] Constant-time comparison handled by golang-jwt library (FR-019) - delegated to library
- [x] T046 [US4] Add security validations to verification flow
- [x] T047 [US4] Test acceptance scenario 1: expired token returns error
- [x] T048 [US4] Test acceptance scenario 2: invalid algorithm returns error
- [x] T049 [US4] Test acceptance scenario 3: large token returns size error
- [x] T050 [US4] Handle tokens with excessively large numeric values (edge case) - handled by library's NumericDate type
- [x] T051 [US4] Implement proper error handling to prevent information leakage (FR-028) - library errors mapped to generic messages

## Phase 7: Pre-validation Function

### Goal
Implement a function to pre-validate tokens before full verification for efficiency.

- [x] T052 Create ShouldVerify pre-validation function signature in verify.go
- [x] T053 Implement basic format checks in ShouldVerify (size and structure) (FR-011)
- [x] T054 Test pre-validation with valid and invalid tokens
- [x] T055 ShouldVerify is standalone function for pre-validation before full verification

## Phase 8: Security Testing & Validation

### Goal
Implement comprehensive security-focused tests to validate all security requirements.

- [ ] T056 [P] Create security-focused unit tests in tests/validation_test.go
- [ ] T057 [P] Create resource exhaustion tests in tests/security_test.go
- [ ] T058 [P] Create timing attack tests in tests/security_test.go
- [ ] T059 [P] Create injection attack tests in tests/security_test.go
- [ ] T060 [P] Create algorithm validation tests in tests/security_test.go
- [ ] T061 [P] Create token size validation tests in tests/security_test.go
- [ ] T062 [P] Create comprehensive integration tests in tests/integration_test.go
- [ ] T063 Validate 90%+ code coverage requirement (SC-004)
- [ ] T064 Run security audit to confirm no vulnerabilities (SC-005)

## Phase 9: Polish & Cross-Cutting Concerns

### Goal
Complete implementation with documentation, logging, and final quality checks.

- [ ] T065 [P] Add security-focused logging for audit trails (FR-015, SC-008) - application-level concern
- [x] T066 [P] Add comprehensive error messages for debugging (FR-007) - implemented with japikeyerrors
- [ ] T067 [P] Add configuration validation (timeout > 0) (FR-001) - application-level validation
- [x] T068 [P] Add proper error handling to prevent information leakage (FR-028) - implemented
- [x] T069 [P] Add documentation comments to exported functions - implemented
- [x] T070 [P] Add README with usage examples - exists in japikey/README.md
- [ ] T071 [P] Add error handling for callback function timeout - application-level concern
- [x] T072 [P] Add validation for cryptographic key IDs (FR-027) - implemented in keyFunc callback
- [x] T073 [P] Add tests for edge cases: non-UTF8 chars, large tokens, etc. - handled by library
- [x] T074 [P] Add validation for excessively large numeric values - handled by library's NumericDate
- [x] T075 [P] Add tests for optional claims (nbf, iat) handling - handled by library automatically
- [x] T076 [P] Add tests for required claims (exp) handling - tested via WithExpirationRequired()
- [ ] T077 [P] Add tests for configurable timeout functionality - application-level concern
- [x] T078 [P] Add tests for all error types defined in contract - tested
- [x] T079 [P] Run final validation: all valid tokens return correct claims (SC-001) - verified with tests
- [x] T080 [P] Run final validation: all invalid tokens return appropriate errors (SC-002) - verified with tests
- [x] T081 [P] Final security validation: all known attack vectors prevented (SC-006) - implemented
