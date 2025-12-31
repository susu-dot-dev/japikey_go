# Implementation Tasks: JAPIKey Signing Library

**Feature**: JAPIKey Signing Library
**Branch**: `002-japikey-signing`
**Date**: December 29, 2025

## Implementation Strategy

This implementation will follow an iterative, test-driven development approach, starting with the simplest possible implementation and building up functionality incrementally. The strategy prioritizes delivering a working, testable implementation of User Story 1 first, then adding validation and error handling, followed by additional features.

**MVP Scope**: User Story 1 implementation with basic JWT creation functionality that works correctly.

## Phase 1: Setup

### Goal
Initialize the project structure and set up dependencies as specified in the implementation plan.

### Tasks
- [X] T001 Initialize go module for japikey library
- [X] T002 Set up go.mod with required dependencies (golang-jwt/jwt/v5, golang.org/x/crypto)
- [X] T003 Create project directory structure (japikey/, internal/crypto/, tests/)

## Phase 2: User Story 1 - Basic Implementation (Priority: P1)

### Goal
Implement the core functionality to create a JAPIKey with mandatory fields (subject, issuer, audience, expiration time) following TDD approach.

### Independent Test Criteria
Can be fully tested by calling the create function with valid mandatory parameters and verifying that a properly formatted JWT is returned with the correct claims.

### Tasks
- [X] T004 [P] [US1] Write failing unit test for CreateJAPIKey with valid inputs (TDD)
- [X] T005 [P] [US1] Create sign.go with basic CreateJAPIKey function signature
- [X] T006 [US1] Define Config struct in sign.go with mandatory fields (subject, issuer, audience, expiration)
- [X] T007 [US1] Define Result struct in sign.go with JWT, Claims, SigningMethod, PublicKey, KeyID
- [X] T008 [US1] Implement basic RSA key pair generation (2048-bit) using crypto/rsa
- [X] T009 [US1] Implement basic JWT creation with RS256 algorithm using golang-jwt
- [X] T010 [US1] Return JWT string and basic Result struct from CreateJAPIKey
- [X] T011 [US1] Run test to verify basic implementation works (T004 should now pass)

## Phase 3: User Story 1 - Add Validation & Error Handling (Priority: P1)

### Goal
Add input validation and structured error handling to the core functionality following TDD approach.

### Independent Test Criteria
Can be tested by providing various invalid inputs (expired date, empty subject, etc.) and verifying appropriate structured error responses with specific error codes.

### Tasks
- [X] T012 [P] [US1] Write failing unit test for CreateJAPIKey with expired time (TDD)
- [X] T013 [P] [US1] Write failing unit test for CreateJAPIKey with empty subject (TDD)
- [X] T014 [US1] Define JAPIKeyValidationError struct in sign.go with error interface implementation
- [X] T015 [US1] Define JAPIKeyGenerationError struct in sign.go with error interface implementation
- [X] T016 [US1] Define JAPIKeySigningError struct in sign.go with error interface implementation
- [X] T017 [US1] Implement input validation for mandatory fields (subject, expiration)
- [X] T018 [US1] Return appropriate validation errors for invalid inputs
- [X] T019 [US1] Run tests to verify validation works (T012, T013 should now pass)

## Phase 4: User Story 1 - Complete Implementation (Priority: P1)

### Goal
Complete the core functionality with all required features following TDD approach.

### Independent Test Criteria
Can be fully tested by calling the create function with valid mandatory parameters and verifying that a properly formatted JWT is returned with the correct claims, version identifier, and key ID.

### Tasks
- [X] T020 [P] [US1] Write failing unit test for version identifier in JWT claims (TDD)
- [X] T021 [P] [US1] Write failing unit test for key ID in JWT header (TDD)
- [X] T022 [P] [US1] Write failing unit test for JWK return in Result (TDD)
- [X] T023 [US1] Create jwk.go with JWK generation functions
- [X] T024 [US1] Implement key ID generation using uuidv7
- [X] T025 [US1] Embed version identifier 'japikey-v1' in JWT claims
- [X] T026 [US1] Add key ID to JWT header
- [X] T027 [US1] Return JWK in Result struct
- [X] T028 [US1] Discard private key after signing to ensure it's never stored
- [X] T029 [US1] Run tests to verify complete implementation (T020, T021, T022 should now pass)

## Phase 5: User Story 2 - Optional Claims (Priority: P2)

### Goal
Extend the core functionality to allow including additional custom claims when creating a JAPIKey following TDD approach.

### Independent Test Criteria
Can be tested by calling the create function with optional claims and verifying that the JWT contains both mandatory and optional claims.

### Tasks
- [X] T030 [P] [US2] Write failing unit test for optional claims functionality (TDD)
- [X] T031 [US2] Update Config struct to include optional Claims field
- [X] T032 [US2] Modify CreateJAPIKey function to include optional claims in JWT
- [X] T033 [US2] Run test to verify optional claims work (T030 should now pass)

## Phase 6: User Story 3 - Advanced Error Handling (Priority: P1)

### Goal
Implement error handling for cryptographic and signing failures following TDD approach.

### Independent Test Criteria
Can be tested by simulating cryptographic and signing failures and verifying appropriate structured error responses.

### Tasks
- [X] T034 [P] [US3] Write failing unit test for cryptographic failure scenarios (TDD)
- [X] T035 [P] [US3] Write failing unit test for signing failure scenarios (TDD)
- [X] T036 [US3] Implement JAPIKeyGenerationError for cryptographic failures
- [X] T037 [US3] Implement JAPIKeySigningError for signing failures
- [X] T038 [US3] Verify type assertions work for specific error handling
- [X] T039 [US3] Run tests to verify advanced error handling (T034, T035 should now pass)

## Phase 7: Security & Performance Testing

### Goal
Implement security-focused tests and performance validation to ensure the implementation meets requirements.

### Tasks
- [X] T040 [P] Write security tests for private key handling
- [X] T041 [P] Write security tests for thread safety
- [X] T042 [P] Write performance tests to validate <100ms generation time
- [X] T043 [P] Write concurrent API key generation tests
- [X] T044 [P] Validate JWT signature verification with returned public key
- [X] T045 [P] Test that private key is never accessible after creation

## Phase 8: Polish & Cross-Cutting Concerns

### Goal
Complete the implementation with documentation, examples, and final validation.

### Tasks
- [X] T046 [P] Add comprehensive documentation to exported functions
- [X] T047 [P] Create example usage files based on quickstart guide
- [X] T048 [P] Add README with installation and usage instructions
- [X] T049 [P] Implement thread safety for any shared resources
- [X] T050 [P] Add integration tests combining all components
- [X] T051 [P] Run all tests to ensure everything works together
- [X] T052 [P] Perform final validation against success criteria

## Dependencies

### User Story Completion Order
1. User Story 1 (P1) - Core functionality (iterative implementation)
2. User Story 2 (P2) - Optional claims extension
3. User Story 3 (P1) - Advanced error handling
4. Security & Performance Testing - Validation
5. Polish & Cross-Cutting Concerns - Finalization

### Task Dependencies
- T004-T011 must be completed before T012-T019 (basic functionality needed before validation)
- T004-T019 must be completed before T020-T029 (validation needed before complete implementation)
- T004-T029 must be completed before T030-T033 (core functionality needed for optional claims)
- T004-T033 must be completed before T034-T039 (core functionality needed for advanced error handling)

## Parallel Execution Examples

### Per User Story
- **User Story 1**: Tasks T004-T005 can run in parallel, and T012-T013 can run in parallel
- **User Story 3**: T034-T035 can be done in parallel, followed by T036-T039

### Cross-Story Parallelization
- Security tests (T040-T045) can be developed in parallel with User Story 2 and 3 implementation
- Documentation (T046-T048) can be worked on in parallel with testing phases