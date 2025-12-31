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

### JWKS Serialization Process
1. Input: JWKS struct
2. Transformation: Wrap single JWK in "keys" array
3. Serialization: Convert to JSON format following RFC 7517
4. Output: JSON string representing JWKS
5. Immutability: Once created, fields cannot be changed externally

### JWKS Deserialization Process
1. Input: JSON string representing JWKS
2. Validation: Verify structure follows RFC 7517 (keys array with exactly one key) - only at unmarshalling
3. Validation: Verify JWK parameters are valid (kty="RSA", valid n and e) - only at unmarshalling
4. Transformation: Extract single JWK from keys array
5. Output: JWKS struct
6. Immutability: Once created, fields cannot be changed externally

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