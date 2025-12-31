---

description: "Task list template for feature implementation"
---

# Tasks: Developer Experience

**Input**: Design documents from `/specs/001-dev-experience/`
**Prerequisites**: plan.md (required), spec.md (required for user stories), research.md, data-model.md, contracts/

**Tests**: The examples below include test tasks. Tests are OPTIONAL - only include them if explicitly requested in the feature specification.

**Organization**: Tasks are grouped by user story to enable independent implementation and testing of each story.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3)
- Include exact file paths in descriptions

## Path Conventions

- **Single project**: `src/`, `tests/` at repository root
- **Web app**: `backend/src/`, `frontend/src/`
- **Mobile**: `api/src/`, `ios/src/` or `android/src/`
- Paths shown below assume single project - adjust based on plan.md structure

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Project initialization and basic structure

- [X] T001 Initialize Go module with `go mod init github.com/susu-dot-dev/japikey-go`
- [X] T002 [P] Create project directory structure: example/, docs/, .github/workflows/
- [X] T003 [P] Install required dependencies: github.com/golang-jwt/jwt/v5, golang.org/x/crypto

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

Examples of foundational tasks (adjust based on your project):

- [X] T004 Create Makefile with commands for local development and CI consistency
- [X] T005 [P] Set up basic README.md with installation and local development instructions
- [X] T006 [P] Configure linter (golangci-lint) for the project
- [X] T007 Create go.mod and go.sum files with Go 1.21 requirement
- [X] T008 Set up basic error handling and logging infrastructure

**Checkpoint**: Foundation ready - user story implementation can now begin in parallel

---

## Phase 3: User Story 1 - New Developer Setup (Priority: P1) 🎯 MVP

**Goal**: Enable new developers on Linux or Mac to easily set up their development environment and run tests successfully

**Independent Test**: A new developer on Linux or Mac can follow the CONTRIBUTING.md guide from zero to having a working development environment with tests running successfully.

### Tests for User Story 1 (OPTIONAL - only if tests requested) ⚠️

> **NOTE: Write these tests FIRST, ensure they FAIL before implementation**

- [ ] T009 [P] [US1] Create basic test for development environment setup in tests/integration/test_setup.py
- [ ] T010 [P] [US1] Create test for linter functionality in tests/integration/test_lint.py

### Implementation for User Story 1

- [X] T011 [P] [US1] Create CONTRIBUTING.md with clear setup instructions for Linux and Mac
- [X] T012 [P] [US1] Add setup instructions for Go 1.21+ requirement
- [X] T013 [US1] Update README.md with developer setup instructions and Makefile usage
- [X] T014 [US1] Add documentation for supported platforms (Linux and Mac only)
- [X] T015 [US1] Add troubleshooting section for common setup issues

**Checkpoint**: At this point, User Story 1 should be fully functional and testable independently

---

## Phase 4: User Story 2 - Example Module (Priority: P1)

**Goal**: Create a minimal example that demonstrates basic module structure and usage

**Independent Test**: A developer can examine the example and understand the basic project layout and usage.

### Tests for User Story 2 (OPTIONAL - only if tests requested) ⚠️

- [X] T016 [P] [US2] Create example test file example/example_test.go with tests for japikey functionality
- [X] T017 [P] [US2] Add benchmark test for example in example/example_test.go

### Implementation for User Story 2

- [X] T018 [P] [US2] Create example demonstrating japikey usage in example/main.go
- [X] T019 [US2] Implement example that shows how to create JAPIKeys in example/main.go
- [X] T020 [US2] Add proper documentation comments to example code
- [X] T021 [US2] Update Makefile to include example in build and test processes
- [X] T022 [US2] Verify example runs correctly

**Checkpoint**: At this point, User Stories 1 AND 2 should both work independently

---

## Phase 5: User Story 3 - Library Usage Quickstart (Priority: P2)

**Goal**: Provide a clear quickstart guide in the README that enables external developers to integrate the library quickly

**Independent Test**: A developer can read the quickstart guide and successfully import and use the library in a new Go project within 10 minutes.

### Tests for User Story 3 (OPTIONAL - only if tests requested) ⚠️

- [X] T023 [P] [US3] Create integration test for quickstart example in tests/integration/test_quickstart.go

### Implementation for User Story 3

- [X] T024 [P] [US3] Create quickstart guide in docs/quickstart.md with installation instructions
- [X] T025 [US3] Add basic usage example to quickstart guide using example
- [X] T026 [US3] Update README.md with quickstart section for external users
- [X] T027 [US3] Add requirements section to quickstart guide (Go 1.21+, Linux/Mac)
- [X] T028 [US3] Include next steps section referencing example in quickstart guide

**Checkpoint**: All user stories should now be independently functional

---

## Phase N: Polish & Cross-Cutting Concerns

**Purpose**: Improvements that affect multiple user stories

- [X] T029 [P] Documentation updates in docs/
- [X] T030 Code cleanup and refactoring
- [X] T031 Performance optimization across all stories
- [X] T032 [P] Additional unit tests (if requested) in tests/unit/
- [X] T033 Security hardening
- [X] T034 Set up GitHub Actions CI workflow in .github/workflows/ci.yml to run tests, linters, and basic functionality checks on Linux
- [X] T035 Run quickstart.md validation

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies - can start immediately
- **Foundational (Phase 2)**: Depends on Setup completion - BLOCKS all user stories
- **User Stories (Phase 3+)**: All depend on Foundational phase completion
  - User stories can then proceed in parallel (if staffed)
  - Or sequentially in priority order (P1 → P2 → P3)
- **Polish (Final Phase)**: Depends on all desired user stories being complete

### User Story Dependencies

- **User Story 1 (P1)**: Can start after Foundational (Phase 2) - No dependencies on other stories
- **User Story 2 (P2)**: Can start after Foundational (Phase 2) - May integrate with US1 but should be independently testable
- **User Story 3 (P3)**: Can start after Foundational (Phase 2) - May integrate with US1/US2 but should be independently testable

### Within Each User Story

- Tests (if included) MUST be written and FAIL before implementation
- Models before services
- Services before endpoints
- Core implementation before integration
- Story complete before moving to next priority

### Parallel Opportunities

- All Setup tasks marked [P] can run in parallel
- All Foundational tasks marked [P] can run in parallel (within Phase 2)
- Once Foundational phase completes, all user stories can start in parallel (if team capacity allows)
- All tests for a user story marked [P] can run in parallel
- Models within a story marked [P] can run in parallel
- Different user stories can be worked on in parallel by different team members

---

## Parallel Example: User Story 1

```bash
# Launch all setup tasks for User Story 1 together:
Task: "Create CONTRIBUTING.md with clear setup instructions for Linux and Mac"
Task: "Add setup instructions for Go 1.21+ requirement"
```

---

## Implementation Strategy

### MVP First (User Story 1 Only)

1. Complete Phase 1: Setup
2. Complete Phase 2: Foundational (CRITICAL - blocks all stories)
3. Complete Phase 3: User Story 1
4. **STOP and VALIDATE**: Test User Story 1 independently
5. Deploy/demo if ready

### Incremental Delivery

1. Complete Setup + Foundational → Foundation ready
2. Add User Story 1 → Test independently → Deploy/Demo (MVP!)
3. Add User Story 2 → Test independently → Deploy/Demo
4. Add User Story 3 → Test independently → Deploy/Demo
5. Each story adds value without breaking previous stories

### Parallel Team Strategy

With multiple developers:

1. Team completes Setup + Foundational together
2. Once Foundational is done:
   - Developer A: User Story 1
   - Developer B: User Story 2
   - Developer C: User Story 3
3. Stories complete and integrate independently

---

## Notes

- [P] tasks = different files, no dependencies
- [Story] label maps task to specific user story for traceability
- Each user story should be independently completable and testable
- Verify tests fail before implementing
- Commit after each task or logical group
- Stop at any checkpoint to validate story independently
- Avoid: vague tasks, same file conflicts, cross-story dependencies that break independence