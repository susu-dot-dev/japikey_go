# Data Model: JAPIKey Signing Library

## Entities

### Config
- **Purpose**: Configuration struct for API key creation parameters
- **Fields**:
  - Subject (string): The subject identifier (required, non-empty)
  - Issuer (string): The issuer identifier (required, valid URL format)
  - Audience (string): The audience identifier (required)
  - ExpiresAt (time.Time): The expiration time (required, in the future)
  - Claims (jwt.MapClaims): Additional optional claims to include in the JWT
- **Validation**:
  - Subject must not be empty
  - ExpiresAt must be in the future
  - Issuer must be a valid URL format
- **Location**: Defined in japikey/sign.go

### JAPIKey
- **Purpose**: JAPIKey struct containing the generated API key and related data
- **Fields**:
  - JWT (string): The signed JWT token
  - PublicKey (*rsa.PublicKey): The RSA public key for verification
  - KeyID (string): The unique identifier for the key pair (uuidv7 format)
- **Relationships**: Contains the output of a successful API key creation
- **Location**: Defined in japikey/sign.go

### JAPIKeyValidationError
- **Purpose**: Error type for validation failures
- **Fields**:
  - Message (string): Human-readable error message
  - Code (string): Error code identifier (ValidationError)
- **Implementation**: Implements the error interface
- **Usage**: Returned when input parameters fail validation
- **Location**: Defined in japikey/sign.go

### JAPIKeyGenerationError
- **Purpose**: Error type for cryptographic failures
- **Fields**:
  - Message (string): Human-readable error message
  - Code (string): Error code identifier (KeyGenerationError)
- **Implementation**: Implements the error interface
- **Usage**: Returned when cryptographic operations fail during key generation
- **Location**: Defined in japikey/sign.go

### JAPIKeySigningError
- **Purpose**: Error type for signing failures
- **Fields**:
  - Message (string): Human-readable error message
  - Code (string): Error code identifier (SigningError)
- **Implementation**: Implements the error interface
- **Usage**: Returned when JWT signing operations fail
- **Location**: Defined in japikey/sign.go

## Relationships
- Config is used as input to generate a Result
- If validation fails, a JAPIKeyValidationError is returned
- If key generation fails, a JAPIKeyGenerationError is returned
- If signing fails, a JAPIKeySigningError is returned
- The Result contains the generated JWT and its corresponding public key (JWK)