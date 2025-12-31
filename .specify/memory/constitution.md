<!--
Sync Impact Report:
- Version change: N/A → 1.0.0 (initial constitution)
- Added sections: All principles and governance sections
- Templates requiring updates: ✅ updated (plan-template.md, spec-template.md, tasks-template.md, checklist-template.md, agent-file-template.md)
- Follow-up TODOs: RATIFICATION_DATE needs to be set
-->
# Japikey Constitution

## Core Principles

### Library-First Architecture
Every feature starts as a standalone library; Libraries must be self-contained, independently testable, documented; Clear purpose required - no organizational-only libraries

### Developer Ease of Use
Usage MUST be documented in a way that encourages easy developer absorption of the library. This includes easy to understand APIs, quickstart and usage examples for every behavior

### Security-First Testing
All core features must be fully tested for correctness from a security posture as well as a functional perspective

### Specification-Driven Development
Tests must be written to validate the correctness of the spec before implementing the features. This ensures that the spec is accurately capturing the behavior, and remains up to date

### Security & Observability
Security-focused logging and monitoring; All security-related events must be logged with appropriate detail for audit trails

### Testing Requirement
No code task can be considered complete unless there are tests validating that it works properly (if tests are feasible). All implementations must include comprehensive unit, integration, and security tests as appropriate for the feature being developed.

### Dependency Utilization
If functionality exists within an already used direct dependency, then it should be preferred over writing our own implementation. This reduces code complexity, potential security vulnerabilities, and maintenance overhead while leveraging well-tested and maintained code.

## Additional Security Requirements

All cryptographic operations must use industry-standard algorithms; Private keys must never be stored or logged; API key validation must include proper issuer verification; All security-sensitive operations must have rate limiting

## Development Workflow

All features must begin with specification and security review; Code reviews must include security-focused validation; Automated security scanning required for all PRs; Documentation must be updated before merge

## Code Quality Standards

All code comments must add value that is not obvious from the code itself. Comments that merely restate the obvious, duplicate what the code clearly expresses, or describe what the code is doing step-by-step are prohibited. Function documentation should be omitted for simple functions where the name clearly indicates its purpose. Comments should focus on the "why" rather than the "what", explaining the reasoning behind complex implementations, security considerations, or non-obvious design decisions. Words describing how things work generally belong in specs, not in code comments.

## Governance
All PRs/reviews must verify compliance with security and library-first principles; Complexity must be justified with security impact assessment; Use README.md for runtime development guidance

**Version**: 1.0.0 | **Ratified**: TODO(RATIFICATION_DATE): Original adoption date unknown | **Last Amended**: 2025-12-29