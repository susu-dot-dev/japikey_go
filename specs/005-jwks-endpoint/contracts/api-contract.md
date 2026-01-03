# API Contract: JWKS Endpoint

**Feature Branch**: `005-jwks-endpoint`
**Date**: January 2, 2026
**Phase**: Phase 1 - Design & Contracts

## Overview

This document specifies the API contract for the JAPIKey JWKS endpoint middleware. The endpoint follows OpenAPI/Swagger specification format.

---

## Endpoint

### Get JWKS for API Key

Retrieves the JSON Web Key Set (JWKS) for a specific API key ID.

**URL Pattern**: `GET /{kid}/.well-known/jwks.json`

**Description**: Returns the public key for a specific API key ID in JWKS format (RFC 7517). The endpoint treats revoked keys and non-existent keys identically by returning 404.

---

## Path Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| kid | string | Yes | The API key ID (UUID) for which to retrieve the public key |

**Constraints**:
- Must be a valid UUID string
- Must not be empty
- Must match the `kid` value embedded in the JAPIKey JWT header

---

## Request

### Headers

| Header | Value | Required | Description |
|--------|-------|----------|-------------|
| Accept | application/json | No | Specifies expected response format |

### Query Parameters

None

### Request Body

None (GET request)

---

## Response

### Success Response (200 OK)

**Condition**: Valid, non-revoked API key found

**Headers**:

| Header | Value | Description |
|--------|-------|-------------|
| Content-Type | application/json | Response format |
| Cache-Control | max-age={seconds} | Caching directive, where {seconds} is the configured cache duration |

**Body**:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "{uuid}",
      "n": "{base64url-modulus}",
      "e": "{base64url-exponent}"
    }
  ]
}
```

**Schema**:

```yaml
type: object
properties:
  keys:
    type: array
    minItems: 1
    maxItems: 1
    items:
      type: object
      required:
        - kty
        - kid
        - n
        - e
      properties:
        kty:
          type: string
          enum: ["RSA"]
          description: Key type (always RSA)
        kid:
          type: string
          format: uuid
          description: Key ID (UUID)
        n:
          type: string
          description: Base64url-encoded RSA modulus
        e:
          type: string
          description: Base64url-encoded RSA exponent
required:
  - keys
```

**Example**:

```json
{
  "keys": [
    {
      "kty": "RSA",
      "kid": "550e8400-e29b-41d4-a716-446655440000",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
  ]
}
```

---

### Error Response: Key Not Found (404 Not Found)

**Condition**: API key ID does not exist in the database OR key has been revoked

**Headers**:

| Header | Value | Description |
|--------|-------|-------------|
| Content-Type | application/json | Response format |

**Body**:

```json
{
  "code": "KeyNotFoundError",
  "message": "API key not found"
}
```

**Schema**:

```yaml
type: object
required:
  - code
  - message
properties:
  code:
    type: string
    enum: ["KeyNotFoundError"]
    description: Error type identifier
  message:
    type: string
    description: Human-readable error message
```

**Example**:

```json
{
  "code": "KeyNotFoundError",
  "message": "API key not found"
}
```

---

### Error Response: Service Unavailable (503 Service Unavailable)

**Condition**: Database is temporarily unavailable or query timed out

**Headers**:

| Header | Value | Description |
|--------|-------|-------------|
| Content-Type | application/json | Response format |

**Body**:

```json
{
  "code": "InternalError",
  "message": "Database temporarily unavailable"
}
```

**Schema**:

```yaml
type: object
required:
  - code
  - message
properties:
  code:
    type: string
    enum: ["InternalError"]
    description: Error type identifier
  message:
    type: string
    description: Human-readable error message
```

**Example**:

```json
{
  "code": "InternalError",
  "message": "Database temporarily unavailable"
}
```

---

### Error Response: Internal Server Error (500 Internal Server Error)

**Condition**: Unexpected database error or system failure

**Headers**:

| Header | Value | Description |
|--------|-------|-------------|
| Content-Type | application/json | Response format |

**Body**:

```json
{
  "code": "InternalError",
  "message": "Internal server error"
}
```

**Schema**:

```yaml
type: object
required:
  - code
  - message
properties:
  code:
    type: string
    enum: ["InternalError"]
    description: Error type identifier
  message:
    type: string
    description: Human-readable error message
```

**Example**:

```json
{
  "code": "InternalError",
  "message": "Internal server error"
}
```

---

## Response Codes Summary

| HTTP Status | Code | Description | Retry Recommendation |
|-------------|------|-------------|---------------------|
| 200 OK | - | Valid key found, JWKS returned | N/A (success) |
| 404 Not Found | KeyNotFoundError | Key not found or revoked | Do not retry (key is invalid) |
| 503 Service Unavailable | InternalError | Database unavailable or timeout | Retry with exponential backoff |
| 500 Internal Server Error | InternalError | Unexpected error | Retry with exponential backoff |

---

## Caching Behavior

### Client-Side Caching

Controlled by `Cache-Control` header:

- `max-age=0`: Do not cache (default)
- `max-age=300`: Cache for 300 seconds
- `max-age={n}`: Cache for n seconds

### Caching Recommendations for Clients

1. **Freshness**: Clients should respect the `Cache-Control` header
2. **Revocation**: Shorter cache times enable faster revocation detection
3. **Performance**: Longer cache times reduce server load
4. **Revalidation**: Consider revalidating cached JWKS periodically for security

---

## Security Considerations

### Data Exposure

- Only public key information is returned
- Private keys are never exposed
- Error messages do not reveal database details
- Revoked keys are indistinguishable from non-existent keys

### Validation

- kid must be a valid UUID
- JWKS follows RFC 7517 specification
- All responses are validated against schema
- No sensitive information in logs

### Rate Limiting

- Rate limiting is out of scope for this middleware
- Applications should implement rate limiting at router/gateway level

---

## Examples

### Example 1: Successful Request

**Request**:

```http
GET /abc123/.well-known/jwks.json HTTP/1.1
Host: example.com
Accept: application/json
```

**Response**:

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: max-age=300

{
  "keys": [
    {
      "kty": "RSA",
      "kid": "abc123",
      "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
      "e": "AQAB"
    }
  ]
}
```

---

### Example 2: Key Not Found

**Request**:

```http
GET /nonexistent/.well-known/jwks.json HTTP/1.1
Host: example.com
Accept: application/json
```

**Response**:

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{
  "code": "KeyNotFoundError",
  "message": "API key not found"
}
```

---

### Example 3: Revoked Key

**Request**:

```http
GET /revoked-key/.well-known/jwks.json HTTP/1.1
Host: example.com
Accept: application/json
```

**Response**:

```http
HTTP/1.1 404 Not Found
Content-Type: application/json

{
  "code": "KeyNotFoundError",
  "message": "API key not found"
}
```

---

### Example 4: Database Unavailable

**Request**:

```http
GET /abc123/.well-known/jwks.json HTTP/1.1
Host: example.com
Accept: application/json
```

**Response**:

```http
HTTP/1.1 503 Service Unavailable
Content-Type: application/json

{
  "code": "InternalError",
  "message": "Database temporarily unavailable"
}
```

---

## OpenAPI 3.0 Specification

```yaml
openapi: 3.0.0
info:
  title: JAPIKey JWKS Endpoint
  version: 1.0.0
  description: |
    API contract for the JAPIKey JWKS endpoint middleware.
    Serves JWKS (JSON Web Key Set) for API key verification.

servers:
  - url: /jwks
    description: Base path (application-configurable)

paths:
  /{kid}/.well-known/jwks.json:
    get:
      summary: Get JWKS for API Key
      description: |
        Retrieves the public key for a specific API key ID in JWKS format.
        Revoked keys and non-existent keys both return 404.
      operationId: getJWKS
      parameters:
        - name: kid
          in: path
          required: true
          description: API key ID (UUID)
          schema:
            type: string
            format: uuid
      responses:
        '200':
          description: Valid key found, JWKS returned
          headers:
            Cache-Control:
              description: Caching directive
              schema:
                type: string
              example: "max-age=300"
          content:
            application/json:
              schema:
                type: object
                required:
                  - keys
                properties:
                  keys:
                    type: array
                    minItems: 1
                    maxItems: 1
                    items:
                      type: object
                      required:
                        - kty
                        - kid
                        - n
                        - e
                      properties:
                        kty:
                          type: string
                          enum: ["RSA"]
                        kid:
                          type: string
                          format: uuid
                        n:
                          type: string
                        e:
                          type: string
        '404':
          description: Key not found or revoked
          content:
            application/json:
              schema:
                type: object
                required:
                  - code
                  - message
                properties:
                  code:
                    type: string
                    enum: ["KeyNotFoundError"]
                  message:
                    type: string
        '503':
          description: Database temporarily unavailable
          content:
            application/json:
              schema:
                type: object
                required:
                  - code
                  - message
                properties:
                  code:
                    type: string
                    enum: ["InternalError"]
                  message:
                    type: string
        '500':
          description: Internal server error
          content:
            application/json:
              schema:
                type: object
                required:
                  - code
                  - message
                properties:
                  code:
                    type: string
                    enum: ["InternalError"]
                  message:
                    type: string
```

---

## Contract Compliance Checklist

- [ ] All endpoints follow specified URL patterns
- [ ] All responses include required headers
- [ ] All error responses follow japikey conventions
- [ ] JWKS format complies with RFC 7517
- [ ] Cache-Control header is always present
- [ ] Content-Type is always application/json
- [ ] Private key information is never exposed
- [ ] Revoked keys return 404
- [ ] Non-existent keys return 404
- [ ] Database errors return appropriate status codes
