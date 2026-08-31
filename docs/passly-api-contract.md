# Passly — API Contract

## 1. `GET /oauth2/authorize`

Initiates the Authorization Code + PKCE flow. This is a browser-redirect endpoint, not a JSON API — the response is an HTTP redirect, first to the identity provider (Google/GitHub) and later back to the client's `redirect_uri`.

### Query Parameters

| Parameter | Required (Passly) | Required per RFC | Type | Description |
|---|---|---|---|---|
| `response_type` | **Required** | Required (RFC 6749) | string | Must be `code` — only Authorization Code flow is supported (Decision 1) |
| `client_id` | **Required** | Required (RFC 6749) | string | Identifies the registered client (`oauth_clients.client_id`) |
| `redirect_uri` | **Required** | Optional (RFC 6749) | URI | Must exactly match one of the client's registered `redirect_uris` — no partial/wildcard matching |
| `scope` | Optional | Optional (RFC 6749) | space-separated string | Requested scopes, e.g. `openid profile email` |
| `state` | **Required** | Optional (RFC 6749) | random string | CSRF protection — mandated by ADR-001 NFR5 regardless of RFC's "SHOULD" |
| `code_challenge` | **Required** | Required if using PKCE (RFC 7636) | Base64URL string | PKCE challenge, derived from `code_verifier` (Decision 1: PKCE is mandatory for every client, not optional) |
| `code_challenge_method` | **Required, fixed to `S256`** | Optional, defaults to `plain` (RFC 7636) | string | Only `S256` is accepted; `plain` is rejected — the RFC default is intentionally not supported |

**Why Passly tightens several RFC-optional fields to required:**
- `state`: RFC 6749 lists it as optional, but ADR-001 (NFR5) treats CSRF protection as a hard requirement for this project — an authorize request without `state` is rejected.
- `code_challenge` / `code_challenge_method=S256`: RFC 7636 makes PKCE opt-in and allows a weak `plain` mode for legacy compatibility. Passly has no legacy clients to support (Decision 1), so PKCE with `S256` is enforced unconditionally — simpler to reason about and removes an entire class of misconfiguration.
- `redirect_uri`: made required in practice (not just recommended) because it is validated against `oauth_clients.redirect_uris` (Entity Design) — an authorize request cannot be safely processed without knowing which registered URI to validate against.

### Success Response
Not a JSON body — a `302 Found` redirect to the identity provider's own login page, after Passly stores `state` and `code_challenge` in Redis (TTL 5 minutes, per Decision 7).

Later, once the user completes login at the IdP and Passly validates the callback, a second `302 Found` redirect is issued to the client's `redirect_uri`:
```
302 Found
Location: https://<redirect_uri>?code=<authorization_code>&state=<state>
```

### Error Responses
| Condition | Response |
|---|---|
| `client_id` unknown / not registered | `302` redirect to `redirect_uri` (if known and valid) with `?error=invalid_client`, otherwise a rendered error page (no safe redirect target) |
| `redirect_uri` not registered for this client | Rendered error page — **must not redirect**, since the URI itself is untrusted at this point |
| `response_type` missing or not `code` | `302` redirect with `?error=unsupported_response_type` |
| `code_challenge` or `code_challenge_method` missing/invalid | `302` redirect with `?error=invalid_request` |
| `state` missing | `302` redirect with `?error=invalid_request` |

---

*(Next: `POST /oauth2/token`)*
