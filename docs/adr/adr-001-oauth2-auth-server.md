# ADR-001: Passly — OAuth2 / OIDC Authorization Server Architecture

## Status
Accepted (draft — pending approval)

## Context
Existing portfolio projects (TenantFlow, ecommerce-system) use custom JWT-based auth mechanisms. No project currently has a standards-compliant OAuth2/OIDC Authorization Server with social login (Google/GitHub). This project is designed as a standalone service to close that gap.

## Requirements

### Functional Requirements
- FR1: Users must be able to log in via Google or GitHub (OAuth2/OIDC delegation)
- FR2: The system must issue an access token (short-lived) and a refresh token (long-lived) on successful login
- FR3: Access tokens must be renewable via the refresh token
- FR4: Independent resource servers must be able to validate these tokens without calling back to the auth server
- FR5: Refresh tokens must be revocable on logout or explicit invalidation
- FR6: The same email address logging in via different providers (Google + GitHub) must resolve to the same user account

### Non-Functional Requirements
- NFR1: Security — resilient against authorization code interception, replay attacks, and CSRF (PKCE required)
- NFR2: Stateless validation — resource servers must not need to call the auth server on every request (performance + reduced coupling)
- NFR3: Horizontal scalability — multiple auth-server instances must be able to run without shared state (a natural consequence of NFR2)
- NFR4: Tokens must be short-lived so that a compromised token has limited impact window (defense in depth)

### Non-Functional Requirements (Security Addendum)

**NFR5 — CSRF Protection via State Parameter:** The authorization request MUST include a cryptographically random `state` parameter, generated per session and bound to the user's session (e.g., stored server-side or in a signed cookie). The authorization server MUST validate that the `state` value returned in the callback matches the one issued for that session before proceeding. This mitigates Cross-Site Request Forgery (CSRF) attacks in which an attacker tricks a victim's browser into completing an authorization flow initiated by the attacker, potentially binding the victim's session to attacker-controlled resources.

**Rationale:** PKCE (NFR1) protects the authorization code exchange from interception and misuse by a malicious app on the same device, but it does not by itself prevent CSRF at the redirect endpoint. The `state` parameter is the standard OAuth2/OIDC mechanism (RFC 6749 §10.12) for this distinct threat, and both protections are required for a complete security posture.

## Decisions

### 1. Grant Type
**Decision:** Authorization Code + PKCE (RFC 7636)
**Rationale:** The OAuth 2.1 draft specification makes PKCE mandatory for public clients. Client Credentials flow is out of scope for now (service-to-service communication is not this project's focus).

### 2. Token Strategy
**Decision:**
- Access token: JWT, signed with RS256, 15-minute lifetime
- Refresh token: opaque (random string), stored in the database, 7-day lifetime, with rotation (invalidated and reissued on every use)
**Rationale:** A short-lived access token combined with rotating refresh tokens is the OAuth 2.1 recommended best practice. Keeping the refresh token opaque (not a JWT) allows it to be revoked server-side via the database.

### 3. Signing
**Decision:** RS256 (asymmetric). The private key stays on the auth server; the public key is published via a JWKS endpoint (`/.well-known/jwks.json`).
**Rationale:** Resource servers can perform stateless validation using the public key without calling the auth server on every request (no introspection). With HMAC, the shared secret would need to be distributed to every service — a larger security surface.

### 4. Social Login / Account Linking
**Decision:** The email returned by Google/GitHub is looked up in the database; if a match exists, the account is linked, otherwise a new user is created. When the same email arrives from a different provider, a record is added to the `linked_accounts` table.
**Rationale:** Email-based matching is simple and can be trusted reliably via OIDC's `email_verified` claim.

### 5. Revocation
**Decision:** Revocation is handled by deleting/invalidating the refresh token record in the database. No separate blacklist exists for access tokens — a 15-minute lifetime is considered sufficient on its own.
**Rationale:** A blacklist mechanism (e.g., Redis) adds extra complexity; a short access-token lifetime combined with refresh rotation is considered adequate by industry standard.

### 6. Resource Server – Auth Server Communication
**Decision:** Stateless validation via JWT + JWKS, not an introspection endpoint.
**Rationale:** Calling the auth server on every request (introspection) introduces coupling and a performance cost. JWKS allows resource servers to validate independently.

## Capacity & Scale Assumptions

Passly is a self-hosted tool: each instance is deployed for a single organization/product, not operated as a multi-tenant SaaS. Design assumptions are sized accordingly:

- **Deployment model:** one Passly instance serves one organization's user base
- **Target scale:** small-to-medium application — roughly 10K–100K registered users, on the order of a few thousand logins per day
- **Peak login traffic:** bursty around typical usage patterns (e.g., morning sign-in spikes) — an assumption of ~50–100 requests/sec at peak is sufficient for v1
- **Token validation traffic:** expected to significantly exceed login traffic, since every API call to a resource server requires token validation, while login happens once per session

**Implications for the design:**
- Stateless token validation (NFR2) is critical precisely because validation traffic dwarfs login traffic — an introspection-based approach (calling back to the auth server on every request) would become the bottleneck at this ratio
- A caching layer (e.g., Redis) is not required purely for scale at this size; however, Redis is still used for a different purpose — see Decision 7 (State / PKCE Challenge Storage) — where its native TTL support, not throughput, is the deciding factor
- Horizontal scalability (NFR3) is a "nice to have, easy to do" property for v1, not a hard requirement — no instance is expected to handle millions of logins per day

## High-Level Architecture

![Passly Component Architecture](./images/passly-component-diagram.svg)

**Component responsibilities:**
- **auth-server:** delegates authentication to Google/GitHub, validates `state` and PKCE, resolves or creates the user (account linking), issues the access token (JWT/RS256) and rotating refresh token (opaque)
- **resource-server:** fetches and caches the public key from the JWKS endpoint, validates JWT signature and claims locally, never calls back to the auth server per request
- **PostgreSQL:** owned solely by auth-server; the resource-server remains stateless and has no database of its own
- **Redis:** stores `state` and PKCE `code_challenge` values with a short TTL (see Decision 7)

This keeps the trust boundary explicit: the auth-server is the single source of truth, and the resource-server never has to trust it implicitly — it verifies independently via signature, consistent with NFR2/NFR3.

### Detailed Flow (Sequence Diagram)

![Passly Authorization Code + PKCE Sequence](./images/passly-sequence-diagram.svg)

The component diagram above shows *who talks to whom*; this sequence diagram shows *the order of operations* for the full Authorization Code + PKCE flow, from the initial authorize request through token issuance and resource-server validation.

### 7. State / PKCE Challenge Storage
**Decision:** Store the `state` parameter and PKCE `code_challenge` in Redis with a short TTL (~5 minutes), rather than in PostgreSQL.
**Rationale:** These values are single-use and inherently short-lived — they exist only for the duration of the authorization round-trip. Redis provides native TTL expiry, avoiding the need for a scheduled cleanup job that a PostgreSQL-based `pending_authorizations` table would require. This does add an extra infrastructure dependency (Redis) to the self-hosted deployment, which was intentionally avoided in the original capacity assumptions — the trade-off was accepted because the operational simplicity of native TTL outweighs the added Docker Compose service for this specific use case.

## Out of Scope (v1)
- Demo/frontend client (to be added in a later phase)
- API Gateway (only two services exist; a gateway would add complexity without a clear routing/rate-limiting need at this stage)
- Client Credentials grant
- Multi-factor authentication
- Dynamic client registration

## Next Step
Once this ADR is approved: project skeleton (auth-server, resource-server modules), entity/table design (users, linked_accounts, refresh_tokens, clients).
