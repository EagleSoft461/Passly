# Passly Authorization Code Issuance - Implementation Plan

> **⚠️ IMPORTANT: This is a PLAN only — DO NOT implement yet. Waiting for approval.**

---

## 📚 Current Architecture Analysis

### ✅ What We Have

**Completed Flow:**
```
Client
  ↓
/oauth2/authorize
  ↓
Validate: client_id, redirect_uri, response_type, state, PKCE
  ↓
AuthorizationRequest → Redis (5 min TTL)
  ↓
Redirect to Google
  ↓
Google Callback
  ↓
State validation + consumption (single-use)
  ↓
Token exchange (authorization code → access_token)
  ↓
UserInfo retrieval (sub, email, email_verified)
  ↓
Account linking/creation
  ↓
User entity ✅
  ↓
⏸️ STOPS HERE - Need to issue Passly authorization code
```

**Redis Infrastructure:**
- ✅ `RedisAuthorizationRequestRepository` exists
- ✅ Pattern: `passly:oauth:authorization:{state}`
- ✅ TTL: 5 minutes (hardcoded constant)
- ✅ Single-use consumption: `getAndDelete()`
- ✅ JSON serialization: Jackson ObjectMapper
- ✅ Proven reliable for state/PKCE storage

**Authorization Request Model:**
```java
record AuthorizationRequest(
    String state,
    String clientId,
    String redirectUri,
    String codeChallenge,
    String codeChallengeMethod,
    String provider,
    Instant expiresAt
)
```

**Domain Models:**
- ✅ `User` (JPA entity)
- ✅ `OAuthClient` (JPA entity)
- ✅ `RefreshToken` (JPA entity with hash storage)
- ⏳ Authorization Code (MISSING - need to create)

---

## 🎯 Proposed Authorization Code Flow

### High-Level Flow

```
GoogleCallbackService.handleCallback()
  ↓
Returns: User (linked account)
  ↓
⭐ NEW: AuthorizationCodeService.issueCode()
  ↓
Input:
  - User userId
  - AuthorizationRequest (contains clientId, redirectUri, PKCE)
  ↓
Generate cryptographically secure random code
  ↓
Create PasslyAuthorizationCode
  {
    code: "generated-code-xyz",
    userId: user.getId(),
    clientId: authRequest.clientId,
    redirectUri: authRequest.redirectUri,
    codeChallenge: authRequest.codeChallenge,
    codeChallengeMethod: authRequest.codeChallengeMethod,
    expiresAt: Instant.now().plus(CODE_TTL),
    consumed: false
  }
  ↓
Store in Redis (plaintext, single-use, short TTL)
  ↓
Return code to GoogleCallbackService
  ↓
⭐ GoogleCallbackController
  ↓
HTTP 302 Redirect:
  Location: {validated_redirect_uri}?code={code}&state={original_state}
  ↓
Client receives code + state
```

### Detailed Decision Flow

```
┌────────────────────────────────────────┐
│ User entity from account linking      │
└────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────┐
│ Q1: Do we have AuthorizationRequest?  │
│     (already consumed from Redis)     │
└────────────────────────────────────────┘
   ↓ YES (stored in callback flow)
┌────────────────────────────────────────┐
│ Q2: Is redirect_uri still valid?      │
│     (defensive check)                 │
└────────────────────────────────────────┘
   ↓ YES
┌────────────────────────────────────────┐
│ Generate Authorization Code            │
│ - SecureRandom 32 bytes → Base64URL   │
│ - Cryptographically secure            │
└────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────┐
│ Create PasslyAuthorizationCode model   │
│ - code (plaintext)                    │
│ - userId                              │
│ - clientId                            │
│ - redirectUri                         │
│ - codeChallenge                       │
│ - codeChallengeMethod                 │
│ - expiresAt (now + 2 minutes)        │
│ - consumed = false                    │
└────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────┐
│ Save to Redis                          │
│ Key: passly:oauth:code:{code}        │
│ TTL: 2 minutes                        │
│ Format: JSON (same as AuthRequest)   │
└────────────────────────────────────────┘
              ↓
┌────────────────────────────────────────┐
│ HTTP 302 Redirect Response            │
│ Location: {redirectUri}               │
│   ?code={generated_code}              │
│   &state={original_state}             │
└────────────────────────────────────────┘
```

---

## 📐 Data Model

### PasslyAuthorizationCode (Redis Model)

```java
/**
 * Represents a Passly authorization code issued after successful external authentication.
 * Stored in Redis with short TTL for single-use consumption.
 *
 * Security:
 * - Code is plaintext (not hashed) since it's short-lived and single-use
 * - TTL ensures automatic cleanup
 * - Single-use enforced via getAndDelete()
 * - Contains PKCE challenge for later verification
 */
public record PasslyAuthorizationCode(
    String code,                    // Cryptographically secure random code
    UUID userId,                    // Linked Passly user
    String clientId,                // OAuth client
    String redirectUri,             // Validated redirect URI
    String codeChallenge,           // PKCE challenge for /oauth2/token verification
    String codeChallengeMethod,     // Always "S256" per ADR-001
    Instant createdAt,              // Issuance timestamp
    Instant expiresAt,              // Expiration timestamp (createdAt + TTL)
    boolean consumed                // Has this code been used? (defensive)
) {
    public PasslyAuthorizationCode {
        if (code == null || code.isBlank()) {
            throw new IllegalArgumentException("code cannot be null or blank");
        }
        if (userId == null) {
            throw new IllegalArgumentException("userId cannot be null");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("clientId cannot be null or blank");
        }
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new IllegalArgumentException("redirectUri cannot be null or blank");
        }
        if (codeChallenge == null || codeChallenge.isBlank()) {
            throw new IllegalArgumentException("codeChallenge cannot be null");
        }
        if (codeChallengeMethod == null || codeChallengeMethod.isBlank()) {
            throw new IllegalArgumentException("codeChallengeMethod cannot be null");
        }
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
```

**Why this design?**
- **Immutable record:** Thread-safe, value semantics
- **All PKCE info preserved:** Needed for /oauth2/token verification
- **Defensive consumed flag:** Extra safety layer (Redis getAndDelete is primary)
- **Validation in constructor:** Fail-fast for invalid data

---

## 💾 Redis/Persistence Strategy

### Storage: Redis (NOT PostgreSQL)

**Rationale:**
```
✅ Short-lived (2 minutes TTL)
✅ Single-use (consume once)
✅ Automatic expiration (native Redis TTL)
✅ No need for cleanup jobs
✅ Consistent with AuthorizationRequest pattern
❌ No need for long-term audit (access/refresh tokens will be in PostgreSQL)
```

**Comparison with existing patterns:**

| Data | Storage | TTL | Reason |
|------|---------|-----|--------|
| AuthorizationRequest | Redis | 5 min | Short-lived, single-use |
| **PasslyAuthorizationCode** | **Redis** | **2 min** | **Short-lived, single-use** |
| RefreshToken | PostgreSQL | 7 days | Long-lived, needs revocation |
| User | PostgreSQL | Permanent | Core entity |

### Redis Key Pattern

```
passly:oauth:code:{authorization_code}
```

**Example:**
```
passly:oauth:code:8xYz3...AbC
→ Value: {"code":"8xYz3...","userId":"123e4567-...","clientId":"demo-client",...}
→ TTL: 120 seconds
```

### Repository Pattern

```java
public interface PasslyAuthorizationCodeRepository {
    /**
     * Saves the authorization code with TTL.
     * The code will automatically expire after the configured duration.
     */
    void save(PasslyAuthorizationCode code);

    /**
     * Consumes (retrieves and deletes) the authorization code.
     * This is an atomic operation ensuring single-use semantics.
     *
     * @return Empty if code doesn't exist, expired, or already consumed
     */
    Optional<PasslyAuthorizationCode> consume(String code);
}
```

**Implementation: RedisPasslyAuthorizationCodeRepository**
- Reuse pattern from `RedisAuthorizationRequestRepository`
- Key prefix: `passly:oauth:code:`
- TTL: 2 minutes (configurable constant)
- JSON serialization: Jackson ObjectMapper
- Consume method: `getAndDelete()` for atomicity

---

## 🔐 Security Model

### 1. Code Generation (Cryptographically Secure)

```java
/**
 * Generates a cryptographically secure random authorization code.
 * Uses SecureRandom with 32 bytes (256 bits) entropy.
 * Encoded as Base64URL for safe URL transmission.
 */
private String generateCode() {
    SecureRandom secureRandom = new SecureRandom();
    byte[] bytes = new byte[32];
    secureRandom.nextBytes(bytes);
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
}
```

**Why 32 bytes?**
- 256 bits of entropy
- Exceeds OAuth 2.0 Security BCP recommendation (128 bits minimum)
- Prevents brute-force attacks
- Base64URL encoding: ~43 characters, URL-safe

### 2. Plaintext vs Hashed Storage

**Decision: Store PLAINTEXT in Redis**

**Rationale:**

| Aspect | Plaintext | Hashed |
|--------|-----------|--------|
| TTL | 2 minutes | 2 minutes |
| Single-use | Yes (getAndDelete) | Yes (getAndDelete) |
| Attack window | Very short | Very short |
| Complexity | Simple | Additional hashing layer |
| Performance | Fast | Hash computation overhead |
| Redis compromise | Codes valid for max 2 min | Marginally better |
| Comparison | RefreshToken (7 days → hash) | AuthCode (2 min → plaintext) |

**Security Analysis:**
```
Threat: Redis data breach
  → Authorization codes valid for max 2 minutes
  → Already consumed codes are deleted (not recoverable)
  → Active window: very small

Mitigation layers:
  1. Short TTL (2 minutes)
  2. Single-use (consumed = deleted)
  3. Network security (Redis not public)
  4. PKCE verification (code alone insufficient for /oauth2/token)

Conclusion: Plaintext acceptable for authorization codes
```

**Industry Standard:**
- Google, GitHub, Microsoft: Authorization codes are short-lived, single-use
- OAuth 2.1 draft: Recommends short TTL + PKCE over code hashing
- Focus: Short lifetime + single-use > cryptographic hashing

### 3. Single-Use Enforcement

**Primary Mechanism: Redis getAndDelete()**
```java
public Optional<PasslyAuthorizationCode> consume(String code) {
    String json = redisTemplate.opsForValue().getAndDelete(key(code));
    // Atomic operation: get + delete in single Redis command
    // Second attempt will return null (already deleted)
}
```

**Defensive Layer: consumed flag**
```java
// In PasslyAuthorizationCode
boolean consumed

// In /oauth2/token handler (future task)
if (authCode.consumed()) {
    throw new InvalidGrantException("Authorization code already used");
}
```

**Race Condition Protection:**
```
Thread 1: consume("code-xyz") → Returns code, deletes from Redis
Thread 2: consume("code-xyz") → Returns empty (already deleted)

Redis guarantees atomicity of getAndDelete()
No additional locking needed
```

### 4. TTL Configuration

**Proposed TTL: 2 minutes**

**Rationale:**
```
OAuth 2.0 BCP: Authorization codes SHOULD be short-lived (10 minutes max recommended)
Our choice: 2 minutes

Why 2 minutes?
- ✅ Long enough: Normal client exchange takes seconds
- ✅ Short enough: Minimizes attack window
- ✅ Consistent: Shorter than AuthorizationRequest (5 min)
- ✅ User experience: No impact (automatic flow)

Configuration:
private static final Duration CODE_TTL = Duration.ofMinutes(2);
```

**TTL Comparison:**
```
AuthorizationRequest (state + PKCE): 5 minutes
  → User needs time to authenticate with Google

PasslyAuthorizationCode: 2 minutes
  → Client immediately exchanges code for token
  → No user interaction needed
```

### 5. Redirect URI Security

**Critical: Use validated redirect_uri from AuthorizationRequest**

```java
// ❌ NEVER do this - untrusted input
String redirectUri = request.getParameter("redirect_uri");

// ✅ ALWAYS use validated URI from authorization phase
String redirectUri = authorizationRequest.redirectUri();
// This URI was validated against oauth_clients.redirect_uris
```

**Why this matters:**
```
Attack scenario:
1. Attacker initiates flow with victim's client_id
2. Attacker provides their own redirect_uri
3. Victim authenticates
4. Authorization code sent to attacker's redirect_uri
5. Attacker steals code

Prevention:
→ redirect_uri validated at /oauth2/authorize
→ Same URI used at callback (no re-validation needed)
→ URI stored in AuthorizationRequest (trusted)
```

### 6. State Parameter Handling

**State MUST be returned to client**

```java
// Redirect URL construction
String redirectUrl = UriComponentsBuilder
    .fromUriString(authorizationRequest.redirectUri())
    .queryParam("code", generatedCode)
    .queryParam("state", authorizationRequest.state())  // ← CRITICAL
    .build()
    .encode()
    .toUriString();
```

**Why state must be returned:**
- CSRF protection for client
- Client validates state matches original request
- OAuth 2.0 spec requirement

### 7. Code Leakage Prevention

**NEVER log authorization codes:**

```java
// ❌ BAD
logger.info("Generated authorization code: " + code);
logger.debug("Code details: {}", authCode);

// ✅ GOOD
logger.info("Authorization code issued: userId={}, clientId={}",
    userId, clientId);
```

**NEVER expose in exception messages:**

```java
// ❌ BAD
throw new CodeGenerationException("Failed to generate code: " + code);

// ✅ GOOD
throw new CodeGenerationException("Failed to generate authorization code");
```

**NEVER return in error responses:**

```java
// Error responses must not leak codes
// Return generic OAuth error codes only
```

---

## ⚠️ Exception Handling

### New Exceptions

#### 1. CodeIssuanceException

```java
/**
 * Thrown when authorization code issuance fails.
 * Generic error to avoid leaking implementation details.
 */
public class CodeIssuanceException extends OAuthAuthorizationException {
    public CodeIssuanceException(String message) {
        super("server_error", message);
    }
}
```

**When to throw:**
- Redis connection failure
- Code generation failure
- Serialization failure

**Security:** Message must NOT contain:
- Generated code
- User ID
- Client ID
- Technical stack traces (in production)

#### 2. InvalidAuthorizationCodeException

```java
/**
 * Thrown when authorization code is invalid, expired, or already consumed.
 * Used in /oauth2/token endpoint (future task).
 */
public class InvalidAuthorizationCodeException extends OAuthAuthorizationException {
    public InvalidAuthorizationCodeException(String message) {
        super("invalid_grant", message);
    }
}
```

**OAuth 2.0 error code:** `invalid_grant`
**HTTP Status:** 400 Bad Request

### Error Scenarios

| Scenario | Exception | Error Code | HTTP Status |
|----------|-----------|------------|-------------|
| Code generation fails | CodeIssuanceException | server_error | 500 |
| Redis save fails | CodeIssuanceException | server_error | 500 |
| Code not found (future) | InvalidAuthorizationCodeException | invalid_grant | 400 |
| Code expired (future) | InvalidAuthorizationCodeException | invalid_grant | 400 |
| Code already used (future) | InvalidAuthorizationCodeException | invalid_grant | 400 |

---

## 🏗️ Proposed Components

### 1. PasslyAuthorizationCode (Model)

**Location:** `authorization/model/`

**Responsibility:** Value object representing issued authorization code

**Fields:**
- code (String)
- userId (UUID)
- clientId (String)
- redirectUri (String)
- codeChallenge (String)
- codeChallengeMethod (String)
- createdAt (Instant)
- expiresAt (Instant)
- consumed (boolean)

### 2. PasslyAuthorizationCodeRepository (Interface)

**Location:** `authorization/repository/`

**Responsibility:** Persistence abstraction for authorization codes

**Methods:**
```java
void save(PasslyAuthorizationCode code);
Optional<PasslyAuthorizationCode> consume(String code);
```

### 3. RedisPasslyAuthorizationCodeRepository (Implementation)

**Location:** `authorization/repository/`

**Responsibility:** Redis-based implementation

**Pattern:** Reuse `RedisAuthorizationRequestRepository` pattern
- Key prefix: `passly:oauth:code:`
- TTL: 2 minutes
- JSON serialization: Jackson
- Atomic consumption: `getAndDelete()`

### 4. AuthorizationCodeService (Service)

**Location:** `authorization/service/`

**Responsibility:** Authorization code issuance business logic

```java
@Service
public class AuthorizationCodeService {

    private static final Duration CODE_TTL = Duration.ofMinutes(2);

    private final PasslyAuthorizationCodeRepository codeRepository;

    /**
     * Issues a Passly authorization code after successful external authentication.
     *
     * @param user The authenticated user
     * @param authorizationRequest The original authorization request (contains PKCE, client, redirect_uri)
     * @return The generated authorization code
     * @throws CodeIssuanceException if code generation or storage fails
     */
    public String issueCode(User user, AuthorizationRequest authorizationRequest) {
        String code = generateCode();

        PasslyAuthorizationCode authCode = new PasslyAuthorizationCode(
            code,
            user.getId(),
            authorizationRequest.clientId(),
            authorizationRequest.redirectUri(),
            authorizationRequest.codeChallenge(),
            authorizationRequest.codeChallengeMethod(),
            Instant.now(),
            Instant.now().plus(CODE_TTL),
            false
        );

        try {
            codeRepository.save(authCode);
            logger.info("Authorization code issued: userId={}, clientId={}",
                user.getId(), authorizationRequest.clientId());
            return code;
        } catch (Exception ex) {
            // Security: Do NOT log the generated code
            throw new CodeIssuanceException("Failed to issue authorization code");
        }
    }

    private String generateCode() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
```

### 5. GoogleCallbackService (Update)

**Current:**
```java
public User handleCallback(String code, String state) {
    // ... existing logic ...
    User user = accountLinkingService.linkOrCreateUser(provider, externalUserInfo);
    return user;
}
```

**After:**
```java
public String handleCallback(String code, String state) {
    // ... existing logic ...
    User user = accountLinkingService.linkOrCreateUser(provider, externalUserInfo);

    // NEW: Issue Passly authorization code
    // Note: We need to preserve AuthorizationRequest for this
    String authorizationCode = authorizationCodeService.issueCode(user, authorizationRequest);

    return authorizationCode;
}
```

**Challenge:** AuthorizationRequest is consumed (deleted) in current flow!

**Solution:** Preserve AuthorizationRequest data before consumption

**Updated Flow:**
```java
public String handleCallback(String code, String state) {
    // ... validate code/state ...

    Optional<AuthorizationRequest> optionalRequest = authorizationRequestService.consume(state);

    if (optionalRequest.isEmpty()) {
        throw new InvalidStateException("Invalid, expired, or already consumed state");
    }

    AuthorizationRequest authRequest = optionalRequest.get();  // ← Save reference

    // ... token exchange, userinfo, account linking ...
    User user = accountLinkingService.linkOrCreateUser(provider, externalUserInfo);

    // NEW: Issue authorization code using preserved authRequest
    String authorizationCode = authorizationCodeService.issueCode(user, authRequest);

    return authorizationCode;
}
```

**Return Type Change:** `User` → `String` (authorization code)

### 6. GoogleCallbackController (Update)

**Current:**
```java
@GetMapping("/login/oauth2/code/google")
public ResponseEntity<CallbackSuccessResponse> googleCallback(...) {
    User user = googleCallbackService.handleCallback(code, state);

    return ResponseEntity.ok(new CallbackSuccessResponse(
        "success", "Account linked successfully", userId
    ));
}
```

**After:**
```java
@GetMapping("/login/oauth2/code/google")
public ResponseEntity<Void> googleCallback(
        @RequestParam(required = false) String code,
        @RequestParam(required = false) String state) {

    // Service returns authorization code
    AuthorizationCodeResponse response = googleCallbackService.handleCallback(code, state);

    // Build redirect URL
    String redirectUrl = UriComponentsBuilder
        .fromUriString(response.redirectUri())
        .queryParam("code", response.authorizationCode())
        .queryParam("state", response.originalState())
        .build()
        .encode()
        .toUriString();

    // HTTP 302 redirect
    return ResponseEntity
        .status(HttpStatus.FOUND)
        .header("Location", redirectUrl)
        .build();
}
```

**Key Changes:**
- Return type: `ResponseEntity<CallbackSuccessResponse>` → `ResponseEntity<Void>`
- Status: 200 OK → 302 Found
- Body: JSON → Empty
- Location header: Redirect to client with code + state

**New Response Model:**

```java
public record AuthorizationCodeResponse(
    String authorizationCode,
    String redirectUri,
    String originalState
) {}
```

---

## 🧪 Test Strategy

### Unit Tests

#### 1. AuthorizationCodeServiceTest

```java
✅ Should generate cryptographically secure code (length, randomness)
✅ Should create PasslyAuthorizationCode with correct fields
✅ Should save code to repository with TTL
✅ Should log issuance (userId + clientId, NOT code)
✅ Should throw CodeIssuanceException on repository failure
✅ Should not leak code in exception messages
✅ Generated codes should be unique (collision test)
✅ Code should be Base64URL encoded (URL-safe)
✅ Should preserve all PKCE information
✅ Should set correct expiration (createdAt + 2 minutes)
```

#### 2. RedisPasslyAuthorizationCodeRepositoryTest

```java
✅ Should save code with correct TTL
✅ Should retrieve code via consume()
✅ Consume should delete code (second call returns empty)
✅ Should return empty for non-existent code
✅ Should handle Redis connection failure
✅ Should correctly serialize/deserialize PasslyAuthorizationCode
✅ Should use correct key prefix (passly:oauth:code:)
✅ TTL should expire after 2 minutes
```

#### 3. GoogleCallbackServiceTest (Updated)

```java
✅ Should complete full flow including code issuance
✅ Should preserve AuthorizationRequest for code issuance
✅ Should return AuthorizationCodeResponse with code + redirect_uri + state
✅ Should handle code issuance failure
✅ Existing tests should still pass (backward compatibility)
```

#### 4. GoogleCallbackControllerTest (Updated)

```java
✅ Should return 302 Found (not 200 OK)
✅ Should include Location header with redirect_uri
✅ Should include code query parameter
✅ Should include state query parameter
✅ Should URL-encode redirect URL
✅ Should return empty body
✅ Should handle code issuance failure (500 error)
```

### Integration Tests (Optional, requires Redis)

```java
✅ End-to-end flow: authorize → callback → code issuance → redirect
✅ Code TTL expiration (wait 2+ minutes, verify code expired)
✅ Single-use enforcement (consume twice, second fails)
✅ Concurrent consumption (two threads, one succeeds)
```

---

## 📁 Files to Create/Modify

### Files to CREATE

#### Models
1. `PasslyAuthorizationCode.java` (record) - `authorization/model/`

#### Repositories
2. `PasslyAuthorizationCodeRepository.java` (interface) - `authorization/repository/`
3. `RedisPasslyAuthorizationCodeRepository.java` (impl) - `authorization/repository/`

#### Services
4. `AuthorizationCodeService.java` - `authorization/service/`

#### Models (Response)
5. `AuthorizationCodeResponse.java` (record) - `authorization/model/`

#### Exceptions
6. `CodeIssuanceException.java` - `authorization/exception/`

#### Tests
7. `AuthorizationCodeServiceTest.java`
8. `RedisPasslyAuthorizationCodeRepositoryTest.java`
9. `PasslyAuthorizationCodeTest.java` (model validation tests)

### Files to MODIFY

#### Services
1. **GoogleCallbackService.java**
   - Add dependency: `AuthorizationCodeService`
   - Preserve `AuthorizationRequest` reference
   - Change return type: `User` → `AuthorizationCodeResponse`
   - Call `authorizationCodeService.issueCode()`
   - Build response with code + redirectUri + state

#### Controllers
2. **GoogleCallbackController.java**
   - Change return type: `ResponseEntity<CallbackSuccessResponse>` → `ResponseEntity<Void>`
   - Change status: 200 OK → 302 Found
   - Add `Location` header with redirect URL
   - Build redirect URL with code + state query params

#### Tests
3. **GoogleCallbackServiceTest.java**
   - Add mock for `AuthorizationCodeService`
   - Update return type assertions
   - Add code issuance tests

4. **GoogleCallbackControllerTest.java**
   - Update expectations: 302 status, Location header
   - Verify query parameters in redirect URL

---

## ⚠️ Risks & Mitigation

### Risk 1: AuthorizationRequest Already Consumed

**Problem:**
```
Current flow:
  authorizationRequestService.consume(state)  ← Deletes from Redis
  ...
  Need authRequest for code issuance, but it's gone!
```

**Mitigation:**
```java
// Preserve reference before consuming
Optional<AuthorizationRequest> optionalRequest = authorizationRequestService.consume(state);
AuthorizationRequest authRequest = optionalRequest.get();  // ← Keep this

// Use later for code issuance
authorizationCodeService.issueCode(user, authRequest);  // ← Still available
```

**Status:** ✅ Not a problem - Java references work as expected

### Risk 2: Code Collision (Birthday Paradox)

**Problem:**
```
Two clients receive same authorization code (random collision)
```

**Analysis:**
```
Code length: 32 bytes = 256 bits
Probability of collision: ~0 for practical usage
Birthday attack: Need 2^128 codes for 50% collision probability

Realistic: System issues <1M codes/day
Collision probability: Negligible (cryptographically impossible)
```

**Mitigation:**
- Use `SecureRandom` (cryptographically secure)
- 32 bytes (256 bits) entropy
- No additional uniqueness check needed

### Risk 3: Redis Connection Failure During Code Save

**Problem:**
```
Code generated, but Redis save fails
→ User stuck, code lost
```

**Mitigation:**
```java
try {
    codeRepository.save(authCode);
} catch (Exception ex) {
    throw new CodeIssuanceException("Failed to issue authorization code");
}
```

**Result:**
- Exception propagated to controller
- HTTP 500 error returned to client
- Client can retry authorization flow
- No data inconsistency (atomic failure)

### Risk 4: Clock Skew (Expiration Edge Cases)

**Problem:**
```
Server 1 generates code: expiresAt = 14:00:00
Server 2 consumes code: currentTime = 14:00:01 (but clock behind by 2 sec)
→ Code appears not expired on Server 2
```

**Mitigation:**
```
Redis TTL is authoritative:
- Redis manages expiration independently
- Clock skew only affects defensive expiration check
- Not a security issue (TTL is primary protection)
```

### Risk 5: Code Leakage in Browser History

**Problem:**
```
Redirect URL: https://client.com/callback?code=SECRET&state=xyz
→ Code visible in browser history
```

**Mitigation:**
- **Out of scope for server** - client responsibility
- OAuth 2.1 recommendation: Use PKCE (we already do)
- Code is single-use and short-lived (2 min)
- PKCE prevents code interception attacks

**Best Practice (for clients):**
- Use POST to /oauth2/token immediately
- Clear query params from URL (history.replaceState)
- Mobile apps: Use custom URI schemes (not our concern)

---

## 🎯 Definition of Done

### Functional Requirements

- ✅ Authorization code generated using SecureRandom (32 bytes)
- ✅ Code stored in Redis with 2-minute TTL
- ✅ Code includes all necessary fields (userId, clientId, PKCE, redirectUri)
- ✅ Single-use enforcement via getAndDelete()
- ✅ HTTP 302 redirect with code + state
- ✅ Redirect URI validation (use trusted URI from AuthorizationRequest)
- ✅ State parameter returned to client

### Security Requirements

- ✅ Code NOT logged anywhere
- ✅ Code NOT in exception messages
- ✅ Code generation cryptographically secure
- ✅ PKCE information preserved for /oauth2/token
- ✅ Redirect URI from validated source only
- ✅ Single-use consumption enforced
- ✅ Short TTL (2 minutes) enforced

### Testing Requirements

- ✅ AuthorizationCodeService unit tests (8+ tests)
- ✅ Repository unit tests (7+ tests)
- ✅ Updated GoogleCallbackService tests
- ✅ Updated GoogleCallbackController tests
- ✅ All existing tests still pass
- ✅ Security scenarios tested (no leakage, single-use)

### Code Quality

- ✅ SOLID principles maintained
- ✅ Consistent with existing patterns (Redis, services)
- ✅ No unnecessary abstractions (YAGNI)
- ✅ Code reuse where appropriate
- ✅ Clear separation of concerns

---

## 📊 Architecture Comparison

### Before vs After

**Before (Current State):**
```
Google Callback
  → State validation
  → Token exchange
  → UserInfo
  → Account linking
  → ❌ STOPS - Returns User to controller
  → Controller returns JSON {"status": "success"}
```

**After (This Implementation):**
```
Google Callback
  → State validation
  → Token exchange
  → UserInfo
  → Account linking
  → ⭐ Authorization code issuance
  → ⭐ HTTP 302 redirect
  → ⭐ Client receives code + state
```

### Consistency with Existing Patterns

| Pattern | AuthorizationRequest | PasslyAuthorizationCode |
|---------|---------------------|------------------------|
| Storage | Redis | Redis ✅ |
| TTL | 5 minutes | 2 minutes ✅ |
| Format | JSON | JSON ✅ |
| Repository | RedisAuthorizationRequestRepository | RedisPasslyAuthorizationCodeRepository ✅ |
| Consumption | getAndDelete() | getAndDelete() ✅ |
| Service | AuthorizationService | AuthorizationCodeService ✅ |
| Naming | passly:oauth:authorization: | passly:oauth:code: ✅ |

---

## 🚀 Next Steps (Out of Scope)

After this implementation, the next task will be:

**`/oauth2/token` Endpoint Implementation**

Requires:
1. Consume authorization code from Redis
2. Verify PKCE (code_verifier against code_challenge)
3. Generate JWT access token (RS256)
4. Generate refresh token (opaque, store in PostgreSQL)
5. Return token response

This task builds on the authorization code we're creating here.

---

## ✅ Summary

**What we're adding:**
- PasslyAuthorizationCode model (Redis)
- Authorization code generation (SecureRandom 32 bytes)
- Redis storage (2-minute TTL, single-use)
- HTTP 302 redirect with code + state
- Comprehensive security controls

**What we're reusing:**
- Redis infrastructure
- Repository pattern
- Service layer pattern
- Exception hierarchy
- Testing patterns

**What we're NOT doing:**
- PostgreSQL storage (unnecessary for short-lived codes)
- Code hashing (unnecessary given short TTL + single-use)
- Complex retry logic (KISS principle)
- GitHub implementation (separate task)
- /oauth2/token endpoint (separate task)

**Security guarantees:**
- ✅ Cryptographically secure generation
- ✅ Single-use enforcement
- ✅ Short TTL (2 minutes)
- ✅ PKCE preserved for verification
- ✅ No code leakage in logs/exceptions
- ✅ Validated redirect URI

---

**Implementation Ready:** YES
**Awaiting Approval:** YES
**Estimated LOC:** ~500 lines (code + tests)
**Estimated Test Count:** +15-20 tests
