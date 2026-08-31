# Passly — Roadmap

Status legend: ✅ Done · 🚧 In Progress · ⬜ Planned

## Phase 0 — Design
- ✅ Requirements (functional + non-functional)
- ✅ Capacity & scale assumptions
- ✅ High-level architecture (component + sequence diagrams)
- ✅ Entity / database design
- ✅ API contract (`/oauth2/authorize`, `/oauth2/token`, `/.well-known/jwks.json`, `/oauth2/revoke`)
- ✅ ADR-001 documented

## Phase 1 — auth-server core
- ✅ Project scaffolded (Spring Boot 4.0.7, Java 21, Maven)
- ✅ Entities + repositories (`User`, `LinkedAccount`, `RefreshToken`, `OAuthClient`)
- ✅ `docker-compose.yml` — PostgreSQL + Redis
- ✅ Seed initial `OAuthClient` configuration — since Dynamic Client Registration is out of scope, clients are provisioned via configuration/seed data at self-hosted deployment time
- ✅ `/oauth2/authorize` — authorization endpoint with Google/GitHub-backed user authentication, mandatory `state` + PKCE
- ✅ Account linking logic (email-based, per Decision 4)
- ✅ `/oauth2/token` — authorization_code grant, PKCE verification
- ✅ `/oauth2/token` — refresh_token grant, rotation
- ✅ Refresh token reuse detection — if a rotated/revoked refresh token is presented again, treat it as a compromise signal and revoke the entire token family
- ✅ RS256 signing key generation + `/.well-known/jwks.json`
- ⬜ `/oauth2/revoke`

## Phase 2 — resource-server
- ⬜ Project scaffolded
- ⬜ JWKS fetching + caching
- ⬜ Local JWT validation (no calls back to auth-server)
- ⬜ Example protected endpoint (`/api/me`)

## Phase 3 — Testing & hardening
- ⬜ Unit tests
    - Token issuance
    - PKCE validation
    - Redirect URI validation (exact-match)
    - Refresh token rotation
    - Refresh token reuse detection
- ⬜ Integration tests (Testcontainers — real PostgreSQL + Redis)
    - Full authorization code + PKCE flow
    - JWKS retrieval and signature validation
    - OAuth error responses (`invalid_grant`, `invalid_client`, etc.)
- ⬜ Manual end-to-end run via Postman (full Authorization Code + PKCE flow)
- ⬜ Security review pass against ADR-001 NFRs

## Phase 4 — Self-hosted packaging
- ⬜ Finalize `.env.example`
- ⬜ `docker-compose up` — single-command full stack
- ⬜ Setup guide in README

## Out of Scope (see ADR-001)
- Demo/frontend client
- API Gateway
- Client Credentials grant
- Multi-factor authentication
- Dynamic Client Registration / Admin API — self-hosted, single-organization tool; not building a multi-tenant client-management product
- Password-based login (`password_hash` on `User`) — Passly is scoped to social login only; adding first-party credentials changes the project's scope
- Rate limiting, audit logging, Prometheus/Grafana observability — deliberately excluded to avoid overlapping with what's already demonstrated in [ecommerce-system](https://github.com/EagleSoft461/ecommerce-system)
- `/userinfo` (OIDC) — deferred, revisit if Passly is used as a real sign-in provider for another project

## Future Considerations (not v1, not ruled out)
- OIDC discovery (`/.well-known/openid-configuration`), ID Token, `nonce` validation
- Consent screen UI ("ExampleApp is requesting: profile, email — Allow / Cancel")
- Key rotation automation (retiring old `kid`s on a schedule, rollover strategy)
- Client secret rotation