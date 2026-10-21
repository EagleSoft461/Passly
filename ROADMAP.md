# Passly — Roadmap

Passly is developed incrementally, with each release representing a meaningful milestone in the evolution of the authorization platform.

**Status legend:** ✅ Done · 🚧 In Progress · 📦 Pre-released · ⬜ Planned · 🔮 Future Consideration

---

## Current Status

**Current release:** `v0.1.0` — Authorization Server Foundation 📦

The core authorization-server foundation is implemented. The project is currently moving toward resource-server integration, integration testing, security hardening, and a complete self-hosted developer experience.

---

# Release v0.1.0 — Authorization Server Foundation

**Status: 📦 Pre-released**

The first milestone establishes the core OAuth 2.x authorization-server capabilities.

### Architecture & Design

* ✅ Functional and non-functional requirements
* ✅ Capacity and scale assumptions
* ✅ High-level component architecture
* ✅ OAuth authorization sequence design
* ✅ Entity / database design
* ✅ API contract
* ✅ ADR-001 — OAuth2 Authorization Server Architecture

### Core Authorization Server

* ✅ Spring Boot 4.0.7 / Java 21 project scaffold
* ✅ Maven project configuration
* ✅ `User` entity and repository
* ✅ `LinkedAccount` entity and repository
* ✅ `RefreshToken` entity and repository
* ✅ `OAuthClient` entity and repository
* ✅ PostgreSQL persistence
* ✅ Redis integration
* ✅ Database migrations with Flyway

### OAuth 2.x Authorization Flow

* ✅ Authorization Code flow
* ✅ PKCE enforcement
* ✅ S256 code challenge validation
* ✅ Mandatory `state` parameter
* ✅ Exact redirect URI validation
* ✅ OAuth client validation
* ✅ Authorization request persistence with TTL
* ✅ Short-lived authorization codes
* ✅ Single-use authorization codes
* ✅ Authorization code → token exchange

### Social Authentication

* ✅ Google authentication
* ✅ GitHub provider foundation
* ✅ External identity abstraction
* ✅ External user information retrieval
* ✅ Provider resolution
* ✅ Email-based account linking
* ✅ Unverified email protection

### Token Infrastructure

* ✅ JWT access tokens
* ✅ RS256 signing
* ✅ RSA key infrastructure
* ✅ JWKS endpoint
* ✅ Opaque refresh tokens
* ✅ Refresh token hashing
* ✅ Refresh token rotation
* ✅ Refresh token reuse detection
* ✅ Token-family revocation on reuse detection

### Developer & Deployment Foundation

* ✅ Docker Compose foundation
* ✅ PostgreSQL + Redis local infrastructure
* ✅ Seed OAuth client configuration
* ✅ Finalize environment configuration
* ✅ Finalize local development setup

### Remaining v0.1.0 Work

* ✅ `/oauth2/revoke`
* ✅ Complete release documentation
* ✅ Validate the complete local OAuth flow

---

# Release v0.2.0 — Resource Server

**Status: ✅ Completed**

The second milestone introduces a reference resource server capable of consuming and validating tokens issued by Passly.

### Resource Server

* ✅ Resource-server project scaffold
* ✅ JWT resource-server configuration
* ⬜ JWKS discovery (deferred to OIDC milestone; v0.2.0 architecture uses explicit `jwk-set-uri` configuration)
* ✅ JWKS endpoint configuration
* ✅ JWKS caching
* ✅ Local JWT signature validation
* ✅ Issuer validation
* ✅ Audience validation
* ✅ Expiration validation
* ✅ Example protected endpoint: `/api/userinfo`
* ✅ Example protected endpoint: `/api/me`

### Architecture Validation

* ✅ Validate auth-server → resource-server trust model
* ✅ Verify that resource requests require no callback to Passly
* ✅ Document token validation architecture ([docs/token-validation-architecture.md](./docs/token-validation-architecture.md))

---

# Release v0.3.0 — Testing & Security Hardening

**Status: ⬜ Planned**

This milestone focuses on protocol correctness, integration reliability, and security hardening.

### Unit Testing

* ⬜ Authorization code issuance
* ⬜ PKCE validation
* ⬜ Redirect URI validation
* ⬜ OAuth client validation
* ⬜ Authorization request validation
* ⬜ Refresh token rotation
* ⬜ Refresh token reuse detection
* ⬜ JWT generation
* ⬜ JWKS functionality
* ⬜ Account linking

### Integration Testing

Using Testcontainers with real infrastructure:

* ⬜ PostgreSQL integration tests
* ⬜ Redis integration tests
* ⬜ Full Authorization Code + PKCE flow
* ⬜ Social authentication callback flow
* ⬜ Authorization code exchange
* ⬜ Refresh token rotation
* ⬜ Refresh token reuse detection
* ⬜ JWKS retrieval
* ⬜ JWT signature validation
* ⬜ OAuth error responses

### End-to-End Validation

* ⬜ Full OAuth flow through Postman
* ⬜ Authorization → callback → code → token flow
* ⬜ Access-token protected resource request
* ⬜ Refresh-token lifecycle validation
* ⬜ Revocation flow validation

### Security Review

* ⬜ Security review against ADR-001 NFRs
* ⬜ OAuth 2.x protocol review
* ⬜ PKCE security review
* ⬜ Redirect URI security review
* ⬜ Token lifecycle review
* ⬜ Secret-handling review

---

# Release v0.4.0 — Self-Hosted Experience

**Status: ⬜ Planned**

The goal of this milestone is to make Passly straightforward to deploy and operate locally or in a self-hosted environment.

### Configuration

* ⬜ Finalize `.env.example`
* ⬜ Document required environment variables
* ⬜ Remove deployment-specific defaults
* ⬜ Document Google OAuth configuration
* ⬜ Document GitHub OAuth configuration

### Docker

* ⬜ Complete `docker-compose.yml`
* ⬜ Single-command local startup
* ⬜ PostgreSQL initialization
* ⬜ Redis initialization
* ⬜ Auth-server startup validation
* ⬜ Resource-server startup validation

### Documentation

* ⬜ Installation guide
* ⬜ Local development guide
* ⬜ OAuth client configuration guide
* ⬜ Provider configuration guide
* ⬜ API documentation
* ⬜ Architecture documentation
* ⬜ Troubleshooting guide

---

# Release v1.0.0 — Stable OAuth 2.x Authorization Server

**Status: ⬜ Planned**

`v1.0.0` represents the first stable release of the Passly OAuth 2.x authorization platform.

### Stability

* ⬜ Complete v0.1–v0.4 milestones
* ⬜ Production-readiness review
* ⬜ Security hardening complete
* ⬜ Integration and E2E test suite complete
* ⬜ Documentation complete
* ⬜ Self-hosted deployment validated

### Protocol

* ⬜ Authorization Code + PKCE fully validated
* ⬜ Token lifecycle fully validated
* ⬜ Refresh token rotation validated
* ⬜ Revocation endpoint validated
* ⬜ JWKS infrastructure validated

### Release

* ⬜ Stable API contract
* ⬜ Versioning policy
* ⬜ Migration guidance
* ⬜ `v1.0.0` release
* ⬜ Stable documentation

---

# Future Considerations

These features are intentionally **not part of the v1 scope** but may be considered in future releases.

### OpenID Connect

* 🔮 `/.well-known/openid-configuration`
* 🔮 ID Tokens
* 🔮 `nonce` validation
* 🔮 `/userinfo`

### User Experience

* 🔮 Consent screen
* 🔮 Application authorization UI
* 🔮 Account management UI

### Cryptographic Infrastructure

* 🔮 Automated signing-key rotation
* 🔮 `kid` rollover strategy
* 🔮 Retiring previous signing keys

### Client Management

* 🔮 Client secret rotation
* 🔮 Dynamic Client Registration
* 🔮 Client management API

---

# Explicitly Out of Scope

The following capabilities are intentionally excluded from the current project scope.

* Demo/frontend client
* API Gateway
* Client Credentials grant
* Password-based authentication
* Multi-factor authentication
* Multi-tenant client-management platform
* Dynamic Client Registration / Admin API
* `/userinfo` and complete OIDC provider functionality in v1
* Registry cleaning
* Unrelated infrastructure/observability features

These exclusions are deliberate architectural decisions rather than unfinished tasks. See **ADR-001** for the reasoning behind the project's scope boundaries.

---

## Release Strategy

Passly follows semantic versioning:

```text
v0.x.x
```

Development releases may introduce architectural changes while the project is evolving.

```text
v1.0.0
```

marks the first stable release with the core OAuth 2.x authorization-server functionality, resource-server reference implementation, security hardening, testing, and self-hosted documentation completed.

## Future Considerations (not v1, not ruled out)
- OIDC discovery (`/.well-known/openid-configuration`), ID Token, `nonce` validation
- Consent screen UI ("ExampleApp is requesting: profile, email — Allow / Cancel")
- Key rotation automation (retiring old `kid`s on a schedule, rollover strategy)
- Client secret rotation
