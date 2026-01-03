# Tasks: JAPIKey JWKS Endpoint Middleware

**Input**: Design documents from `/specs/005-jwks-endpoint/`
**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/api-contract.md
**Tests**: Included - Security-first testing is a constitution requirement and specified in the feature specification
**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3, US4)
- Include exact file paths in descriptions

## Path Conventions

- **Library project**: `internal/middleware/` for new middleware code
- **Tests**: `internal/middleware/jwks_test.go` alongside implementation
- **Re-exports**: `jwks.go` at repository root to export middleware types
- **Existing code**: `internal/jwks/` for JWKS generation (used, not modified)

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [X] T001 Create internal/middleware/ directory structure
- [X] T002 [P] Create jwks.go file with package declaration and imports in internal/middleware/jwks.go
- [X] T003 [P] Create jwks_test.go file with testing imports in internal/middleware/jwks_test.go
- [X] T004 [P] Create internal/middleware/README.md file with documentation
- [X] T004b [P] Create jwks.go at root level to re-export middleware types

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [X] T005 Define DatabaseDriver interface with GetKey() method in internal/middleware/jwks.go
- [X] T006 [P] Add DatabaseTimeout error type to errors/errors.go (for future database operations)
- [X] T007 [P] Add DatabaseUnavailable error type to errors/errors.go (for future database operations)
- [X] T008 [P] Define JWKSHandler struct with db and maxAgeSeconds fields in internal/middleware/jwks.go
- [X] T009 Define CreateJWKSRouter function signature in internal/middleware/jwks.go
- [X] T010 [P] Implement ServeHTTP method skeleton with request logging for 500-class errors in internal/middleware/jwks.go
- [X] T011 [P] Import existing internal/jwks package for JWKS generation in internal/middleware/jwks.go

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - Retrieve JWKS for Valid API Key (Priority: P1) 🎯 MVP

**Goal**: Enable clients to fetch public key for valid, non-revoked API keys to verify JAPIKeys without storing secrets

**Independent Test**: Make HTTP GET request to JWKS endpoint with valid key ID and verify response contains properly formatted JWKS with correct public key, Cache-Control header, and status 200

### Tests for User Story 1 (Security-First Testing)

- [X] T011 [P] [US1] Test valid key returns 200 with JWKS in internal/middleware/jwks_test.go
- [X] T012 [P] [US1] Test Cache-Control header reflects configured max-age in internal/middleware/jwks_test.go
- [X] T013 [P] [US1] Test JWKS response contains exactly one key with correct kty and kid in internal/middleware/jwks_test.go
- [X] T014 [P] [US1] Test JWKS response is valid RFC 7517 format and parseable in internal/middleware/jwks_test.go
- [X] T015 [P] [US1] Test response time is under 100ms for valid requests in internal/middleware/jwks_test.go

### Implementation for User Story 1

- [X] T016 [US1] Implement path parameter extraction using Go 1.22+ PathValue() method in internal/middleware/jwks.go
- [X] T017 [US1] Validate kid format as UUID in internal/middleware/jwks.go
- [X] T018 [US1] Call db.GetKey() with context and kid parameter in internal/middleware/jwks.go
- [X] T019 [US1] Handle successful key retrieval (key not nil, revoked false) in internal/middleware/jwks.go
- [X] T020 [US1] Handle errors.KeyNotFoundError and return 404 in internal/middleware/jwks.go
- [X] T021 [US1] Convert kid string to uuid.UUID type in internal/middleware/jwks.go
- [X] T022 [US1] Call internal/jwks.NewJWKS() with publicKey and kid UUID in internal/middleware/jwks.go
- [X] T023 [US1] Set Content-Type header to application/json in internal/middleware/jwks.go
- [X] T024 [US1] Set Cache-Control header with max-age=maxAgeSeconds in internal/middleware/jwks.go
- [X] T025 [US1] Return 200 OK status with JWKS JSON response in internal/middleware/jwks.go

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently (valid keys return 200 with JWKS)

---

## Phase 4: User Story 2 - Handle Non-Existent API Key Requests (Priority: P1)

**Goal**: Clients receive clear 404 error when requesting JWKS for non-existent API keys to fail fast and not attempt verification with invalid keys

**Independent Test**: Make HTTP GET request to JWKS endpoint with non-existent key ID and verify response is 404 with JSON error and appropriate error details

### Tests for User Story 2 (Security-First Testing)

- [X] T026 [P] [US2] Test non-existent key returns 404 in internal/middleware/jwks_test.go
- [X] T027 [P] [US2] Test 404 response contains errors.KeyNotFoundError code in internal/middleware/jwks_test.go
- [X] T028 [P] [US2] Test 404 response has proper JSON error structure in internal/middleware/jwks_test.go
- [X] T029 [P] [US2] Test no database modifications occur for 404 responses in internal/middleware/jwks_test.go

### Implementation for User Story 2

- [X] T030 [US2] Handle errors.KeyNotFoundError from db.GetKey() in internal/middleware/jwks.go
- [X] T031 [US2] Set Content-Type header to application/json for 404 response in internal/middleware/jwks.go
- [X] T032 [US2] Set Cache-Control header for 404 response (max-age=0) in internal/middleware/jwks.go
- [X] T033 [US2] Return 404 Not Found status with KeyNotFoundError JSON in internal/middleware/jwks.go

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently (valid keys return 200, non-existent return 404)

---

## Phase 5: User Story 3 - Handle Revoked API Key Requests (Priority: P1)

**Goal**: Clients receive 404 error when requesting JWKS for revoked API keys to detect and reject compromised or invalid keys

**Independent Test**: Create API key, revoke it in database, request JWKS endpoint, and verify 404 response

### Tests for User Story 3 (Security-First Testing)

- [X] T034 [P] [US3] Test revoked key returns 404 in internal/middleware/jwks_test.go
- [X] T035 [P] [US3] Test revoked key response identical to non-existent key (cannot distinguish) in internal/middleware/jwks_test.go
- [X] T036 [P] [US3] Test revoked keys never return valid JWKS in internal/middleware/jwks_test.go

### Implementation for User Story 3

- [X] T037 [US3] Handle revoked=true return value from db.GetKey() in internal/middleware/jwks.go
- [X] T038 [US3] Return 404 Not Found for revoked keys (same as non-existent) in internal/middleware/jwks.go

**Checkpoint**: At this point, all P1 user stories should be complete and independently functional

---

## Phase 6: User Story 4 - Configurable Cache Control Header (Priority: P2)

**Goal**: Operators can configure cache duration for JWKS responses to control how long clients cache public key information

**Independent Test**: Configure different cache durations and verify Cache-Control header reflects configured value

### Tests for User Story 4

- [X] T039 [P] [US4] Test maxAgeSeconds=0 sets max-age=0 in internal/middleware/jwks_test.go
- [X] T040 [P] [US4] Test maxAgeSeconds=300 sets max-age=300 in internal/middleware/jwks_test.go
- [X] T041 [P] [US4] Test negative maxAgeSeconds is clamped to 0 (max-age=0) in internal/middleware/jwks_test.go

### Implementation for User Story 4

- [X] T042 [US4] Implement default maxAgeSeconds of 0 (no caching) in internal/middleware/jwks.go
- [X] T043 [US4] Implement clamping of negative maxAgeSeconds to 0 in internal/middleware/jwks.go
- [X] T044 [US4] Apply maxAgeSeconds to Cache-Control header in all response paths in internal/middleware/jwks.go

**Checkpoint**: All user stories should now be independently functional

---

## Phase 7: Database Error Handling (Cross-Cutting)

**Purpose**: Ensure robust error handling for all database failure scenarios

### Tests for Database Error Handling

- [X] T045 [P] Test database timeout returns 503 in internal/middleware/jwks_test.go
- [X] T046 [P] Test database unavailable returns 503 in internal/middleware/jwks_test.go
- [X] T047 [P] Test other database errors return 500 in internal/middleware/jwks_test.go
- [X] T048 [P] Test 500-class errors are logged in internal/middleware/jwks_test.go

### Implementation for Database Error Handling

- [X] T049 Handle errors.DatabaseTimeout from db.GetKey() and return 503 in internal/middleware/jwks.go
- [X] T050 Handle errors.DatabaseUnavailable from db.GetKey() and return 503 in internal/middleware/jwks.go
- [X] T051 Handle other errors from db.GetKey() and return 500 in internal/middleware/jwks.go
- [X] T052 Add logging for all 500-class errors (500, 503) in internal/middleware/jwks.go

---

## Phase 8: Security & Concurrent Request Handling

**Purpose**: Ensure security and thread-safety requirements are met

### Tests for Security & Concurrency

- [X] T053 [P] Test invalid kid format returns 404 in internal/middleware/jwks_test.go
- [X] T054 [P] Test empty kid returns 404 in internal/middleware/jwks_test.go
- [X] T055 [P] Test concurrent requests for same key ID are handled safely in internal/middleware/jwks_test.go
- [X] T056 [P] Test no private key information is exposed in any response in internal/middleware/jwks_test.go
- [X] T057 [P] Test Content-Type is always application/json in internal/middleware/jwks_test.go
- [X] T058 [P] Test JWKS response contains only requested key, never multiple keys in internal/middleware/jwks_test.go

### Implementation for Security & Concurrency

- [X] T059 Ensure no shared state between requests (handler is thread-safe) in internal/middleware/jwks.go
- [X] T060 Ensure all database operations use context for cancellation in internal/middleware/jwks.go
- [X] T061 Ensure read-only database operations (no writes) in internal/middleware/jwks.go
- [X] T062 Ensure error messages do not expose sensitive database details in internal/middleware/jwks.go

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Final improvements, documentation, and validation

- [X] T063 [P] Complete internal/middleware/README.md with installation, usage, configuration, and examples in internal/middleware/README.md
- [X] T064 [P] Add mock database driver implementation examples for testing in internal/middleware/README.md
- [X] T065 [P] Code cleanup and refactoring in internal/middleware/jwks.go
- [X] T066 [P] Add godoc comments to exported types and functions in internal/middleware/jwks.go
- [X] T067 Run all tests to ensure 100% pass rate in internal/middleware/jwks_test.go
- [X] T068 Verify tests fail before implementing (TDD validation)
- [X] T069 Validate quickstart.md examples work with implementation in internal/middleware/jwks_test.go

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Story 1 (Phase 3)**: Depends on Foundational phase completion
- **User Story 2 (Phase 4)**: Depends on Foundational phase completion - Independent of US1/US3
- **User Story 3 (Phase 5)**: Depends on Foundational phase completion - Independent of US1/US2
- **User Story 4 (Phase 6)**: Depends on Foundational phase completion - Independent of US1/US2/US3
- **Database Error Handling (Phase 7)**: Depends on Foundational phase completion - Applies to all stories
- **Security & Concurrency (Phase 8)**: Depends on Foundational phase completion - Applies to all stories
- **Polish (Phase 9)**: Depends on all user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P1)**: Can start after Foundational (Phase 2) - May integrate with US1 but should be independently testable
- **User Story 3 (P1)**: Can start after Foundational (Phase 2) - May integrate with US1/US2 but should be independently testable
- **User Story 4 (P2)**: Can start after Foundational (Phase 2) - Applies to all stories but independently testable

### Within Each User Story

- Tests MUST be written and FAIL before implementation (TDD approach)
- Tests are organized before implementation in each phase
- Story complete when all implementation tasks pass corresponding tests
- Validate story independently before moving to next priority

### Parallel Opportunities

**Phase 1**:
- T002, T003, T004 can run in parallel (different files)

**Phase 2**:
- T006 can run in parallel with others (different part of file)
- T009, T010 can run in parallel with others (different imports/features)

**Phase 3 (User Story 1)**:
- T011, T012, T013, T014, T015 (tests) can all run in parallel once file exists
- T016-T024 must be sequential (build on each other)

**Phase 4 (User Story 2)**:
- T025, T026, T027, T028 (tests) can all run in parallel once file exists
- T029-T032 must be sequential (build on T018 from US1)

**Phase 5 (User Story 3)**:
- T033, T034, T035 (tests) can all run in parallel once file exists
- T036, T037 can run in parallel (simple additions to error handling)

**Phase 6 (User Story 4)**:
- T038, T039, T040 (tests) can all run in parallel once file exists
- T041-T043 must be sequential (build on existing code)

**Phase 7 (Database Error Handling)**:
- T044, T045, T046, T047 (tests) can all run in parallel once file exists
- T048-T051 can run in parallel (different error scenarios)

**Phase 8 (Security & Concurrency)**:
- T052, T053, T054, T055, T056, T057 (tests) can all run in parallel once file exists
- T058, T059, T060, T061 can run in parallel (different concerns)

**Phase 9 (Polish)**:
- T062, T063, T064, T065, T066 can run in parallel (different files/concerns)

**Cross-Story Parallelism**:
- After Phase 2 completes, User Stories 1, 2, 3 can be worked on in parallel by different team members
- User Story 4 (P2) can be worked on in parallel with any other story
- Database Error Handling, Security & Concurrency can be worked on in parallel with user stories

---

## Parallel Example: User Story 1

```bash
# Launch all tests for User Story 1 together (first):
Task: "T012 [P] [US1] Test valid key returns 200 with JWKS in internal/middleware/jwks_test.go"
Task: "T013 [P] [US1] Test Cache-Control header reflects configured max-age in internal/middleware/jwks_test.go"
Task: "T014 [P] [US1] Test JWKS response contains exactly one key with correct kty and kid in internal/middleware/jwks_test.go"
Task: "T015 [P] [US1] Test JWKS response is valid RFC 7517 format and parseable in internal/middleware/jwks_test.go"
Task: "T016 [P] [US1] Test response time is under 100ms for valid requests in internal/middleware/jwks_test.go"

# Verify all tests fail before implementation (TDD validation)

# Then implement User Story 1 sequentially:
Task: "T017 [US1] Implement path parameter extraction using Go 1.22+ PathValue() method in internal/middleware/jwks.go"
Task: "T018 [US1] Validate kid format as UUID in internal/middleware/jwks.go"
# ... continue with remaining US1 implementation tasks
```

---

## Implementation Strategy

### MVP First (User Stories 1, 2, 3 - All P1 Stories)

1. Complete Phase 1: Setup (T001-T004)
2. Complete Phase 2: Foundational (T005-T010) - **CRITICAL**
3. Complete Phase 3: User Story 1 (T011-T024)
4. **STOP and VALIDATE**: Test User Story 1 independently - valid keys return 200 with JWKS
5. Complete Phase 4: User Story 2 (T025-T032)
6. **STOP and VALIDATE**: Test User Story 2 independently - non-existent keys return 404
7. Complete Phase 5: User Story 3 (T033-T037)
8. **STOP and VALIDATE**: Test User Story 3 independently - revoked keys return 404
9. Deploy/demo P1 MVP if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Validate P1 story 1 works
3. Add User Story 2 → Test independently → Validate P1 story 2 works
4. Add User Story 3 → Test independently → Validate P1 story 3 works
5. Add User Story 4 → Test independently → Validate P2 story 4 works
6. Add Database Error Handling → Test → Ensure robust error handling
7. Add Security & Concurrency → Test → Ensure security and thread-safety
8. Complete Polish → Final validation and documentation
9. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup (Phase 1) + Foundational (Phase 2) together - **CRITICAL FIRST STEP**
2. Once Foundational is done:
   - Developer A: User Story 1 (Phase 3) - Core happy path
   - Developer B: User Story 2 (Phase 4) - Error handling for not found
   - Developer C: User Story 3 (Phase 5) - Error handling for revoked keys
3. User Stories 1, 2, 3 can be developed and tested in parallel
4. Once P1 stories are complete, Developer D can work on User Story 4 (Phase 6) in parallel with polish work
5. Team converges on Database Error Handling (Phase 7), Security (Phase 8), and Polish (Phase 9)

---

## Format Validation

✅ **All tasks follow checklist format**:
- Every task starts with `- [ ]`
- Every task has sequential Task ID (T001-T069)
- Parallelizable tasks marked with `[P]`
- User story phase tasks marked with `[US1]`, `[US2]`, `[US3]`, or `[US4]`
- Setup and Foundational phases have NO story labels
- Polish phase has NO story labels
- Every description includes exact file path

✅ **Task Count Summary**:
- **Total tasks**: 69 (T001-T069)
- **Setup tasks**: 4 (T001-T004)
- **Foundational tasks**: 7 (T005-T011)
- **User Story 1 tasks**: 10 (T012-T025)
- **User Story 2 tasks**: 8 (T026-T033)
- **User Story 3 tasks**: 5 (T030-T034)
- **User Story 4 tasks**: 6 (T035-T040)
- **Database Error Handling tasks**: 8 (T045-T052)
- **Security & Concurrency tasks**: 10 (T053-T062)
- **Polish tasks**: 7 (T063-T069)

✅ **Test Coverage**: Tests included for all user stories and cross-cutting concerns (26 test tasks total)

✅ **Independent Test Criteria**:
- **US1**: HTTP GET with valid key ID → 200 with properly formatted JWKS
- **US2**: HTTP GET with non-existent key ID → 404 with JSON error
- **US3**: Create key, revoke it, request JWKS → 404 (same as non-existent)
- **US4**: Configure different cache durations → Cache-Control header matches config

✅ **Parallel Opportunities**:
- Multiple parallelizable tasks identified across all phases
- Test files can be populated in parallel within each user story phase
- Different user stories can be worked on in parallel after Foundational phase
- Cross-cutting concerns (security, error handling) can be worked on in parallel with user stories

✅ **MVP Scope**: User Stories 1, 2, 3 (all P1 stories) - enables core functionality for valid keys, non-existent keys, and revoked keys

---

## Notes

- [P] tasks = different files or no dependencies, can run in parallel
- [Story] label maps task to specific user story for traceability (US1, US2, US3, US4)
- Each user story should be independently completable and testable
- Tests are written BEFORE implementation (TDD approach) as specified
- Verify tests fail before implementing - TDD requirement
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Foundational phase (T005-T011) is CRITICAL - BLOCKS all user stories until complete
- Go 1.22+ PathValue() method required for path parameter extraction
- All error handling follows japikey error conventions (errors package)
- Database error types (DatabaseTimeout, DatabaseUnavailable) are in main errors package for future database operations
- No private key exposure in any response or log (security requirement)
- Revoked keys indistinguishable from non-existent keys (security requirement)
- All database operations are read-only (security requirement)
