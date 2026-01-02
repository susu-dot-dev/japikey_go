# Data Model: JWK Conversion Support

## Entities

### JWK (JSON Web Key)
**Fields**:
- `kty` (string): Always "RSA" to identify the key type (kty parameter)
- `kid` (uuid.UUID): The key identifier that matches the JAPIKey ID (kid parameter), stored as UUID type to enforce UUID format
- `n` (string): The RSA modulus encoded as Base64urlUInt (n parameter)
- `e` (string): The RSA exponent encoded as Base64urlUInt (e parameter)

**Validation Rules**:
- `kty` must be "RSA"
- `kid` must be a valid UUID (enforced by using UUID type internally)
- `n` must be a valid Base64urlUInt-encoded value representing the RSA modulus
- `e` must be a valid Base64urlUInt-encoded value representing the RSA exponent
- All parameters are required

**Immutability**: Once constructed, the struct fields are immutable and can only be modified within the jwks package.

### JWKS (JSON Web Key Set)
**Fields**:
- `keys` ([]JWK): Array containing exactly one JWK

**Validation Rules**:
- `keys` array must contain exactly one key
- All member names within the JWKS must be unique
- Only supports the parameters: "kty", "kid", "n", "e"
- No additional parameters beyond the supported ones are allowed

**Immutability**: Once constructed, the struct fields are immutable and can only be modified within the jwks package.

### JAPIKey (Reference Entity)
**Fields**:
- `KeyID` (uuid.UUID): A UUID that uniquely identifies the JAPIKey, stored as UUID type to enforce UUID format
- `PublicKey` (*rsa.PublicKey): The RSA public key component

**Validation Rules**:
- `KeyID` must be a valid UUID (enforced by using UUID type internally)
- `PublicKey` must not be nil and must be a valid RSA public key

## Relationships

- JAPIKey → JWKS: One-to-one relationship where a JAPIKey can be converted to a JWKS
- JWKS → JWK: One-to-many relationship where a JWKS contains exactly one JWK
- JWK → RSA Parameters: One-to-many relationship where a JWK contains the RSA modulus and exponent

## State Transitions

### JWK Creation Process
1. Input: RSA public key and key ID
2. Validation: Verify key ID is valid UUID and public key is not nil (only at construction)
3. Encoding: Convert RSA modulus and exponent to Base64urlUInt format
4. Output: JWK with kty="RSA", kid=key ID, n=modulus, e=exponent
5. Immutability: Once created, fields cannot be changed externally

### JWKS Serialization Process (MarshalJSON)
1. Input: JWKS struct (in-memory representation with lowercase fields)
2. Transformation: Create `encodedJWKS` struct with `Keys` array containing single `encodedJWK`
3. Field mapping: Copy `kid`, `n`, `e` from in-memory JWK to encoded JWK, set `Kty` to "RSA"
4. Serialization: Use standard `json.Marshal` on `encodedJWKS` struct
5. Output: JSON bytes following RFC 7517 format with "keys" array
6. Immutability: Once created, fields cannot be changed externally

### JWKS Deserialization Process (UnmarshalJSON)

The deserialization process uses a **two-phase validation approach** to ensure strict compliance:

#### Phase 1: JSON Shape Validation (`validateJSONShape`)
1. Input: JSON bytes representing JWKS
2. Untyped unmarshaling: Unmarshal into `struct { Keys []map[string]interface{} }` to detect extra fields
3. Validation checks (all failures return `ValidationError`):
   - Verify JSON is valid (returns "invalid JWKS JSON format: ..." on failure)
   - Verify `keys` array exists and contains exactly one element (returns "JWKS must contain exactly one key" on failure)
   - Verify JWK object contains exactly 4 fields: `kty`, `kid`, `n`, `e` (returns "JWK must contain exactly 4 fields: kty, kid, n, e" on failure)
   - Verify each required field exists (returns "JWK must contain '<field>' field" for missing fields)
4. Purpose: Detect extra fields that Go's typed unmarshaling would silently ignore

#### Phase 2: Typed Unmarshaling and Validation
1. Typed unmarshaling: Unmarshal into `encodedJWKS` struct
2. JSON format validation: If unmarshaling fails, return `ValidationError` with "invalid JWKS JSON format: ..."
3. Extract single JWK: Access `ejwks.Keys[0]` as `encodedJWK`
4. Validate `kty` parameter: Must equal "RSA" (returns `ValidationError` with "kty parameter must be 'RSA'" if not)
5. Decode Base64urlUInt values:
   - Decode `n` (modulus) using `base64urlUIntDecode()` (returns `ValidationError` with "failed to decode modulus: ..." on failure)
   - Decode `e` (exponent) using `base64urlUIntDecode()` (returns `ValidationError` with "failed to decode exponent: ..." on failure)
6. Construct RSA public key: Create `*rsa.PublicKey` from decoded modulus and exponent
7. Use constructor: Call `NewJWKS(publicKey, ejwk.Kid)` to create validated JWKS (re-validates key ID and public key, returns error if validation fails)
8. Round-trip validation: Compare `jwks.jwk.n` and `jwks.jwk.e` with `ejwk.N` and `ejwk.E` to ensure encoding consistency (returns `ConversionError` with "round-trip validation failed: n values do not match" if mismatch)
9. Assignment: Copy validated JWK to target JWKS struct
10. Output: Validated JWKS struct
11. Immutability: Once created, fields cannot be changed externally

**Error Types Used:**
- `ValidationError`: For all validation failures (JSON format, field validation, parameter validation, decoding failures)
- `ConversionError`: For round-trip validation failures (encoding mismatch)

## Constraints

### RFC Compliance
- Must follow RFC 7517 for JWKS structure
- Must follow RFC 7518 for RSA parameter encoding (Base64urlUInt)
- Must follow RFC 7515 Section 2 for base64url encoding without padding
- Must follow RFC 4648 Section 5 for URL-safe character set

### Format Constraints
- Base64urlUInt encoding must use unpadded base64url format (no '=' characters)
- RSA modulus and exponent must be encoded as big-endian byte representation
- Zero values in Base64urlUInt must be represented as "AA" (BASE64URL(single zero-valued octet))
- Octet sequences must utilize the minimum number of octets needed to represent the value

### Immutability Constraints
- Struct variables are treated as immutable after construction
- Validation occurs only at construction or unmarshalling time, not on every function call
- Lowercase field names ensure only the jwks package can update the variables
- All JWKS-related code (except external wrapper) is in internal/ subdirectory with separate jwks package
