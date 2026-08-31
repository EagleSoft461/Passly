# Passly — Database Entity Design (Draft)

## users
| Column | Type | Constraints |
|---|---|---|
| id | UUID | PK, default `gen_random_uuid()` |
| email | VARCHAR(255) | UNIQUE, NOT NULL |
| email_verified | BOOLEAN | NOT NULL, default `false` |
| display_name | VARCHAR(255) | NULL |
| created_at | TIMESTAMPTZ | NOT NULL, default `now()` |
| updated_at | TIMESTAMPTZ | NOT NULL, default `now()` |

**Indexes:** UNIQUE index on `email` (also serves as the lookup index for account linking — Decision 4).

---

## linked_accounts
| Column | Type | Constraints |
|---|---|---|
| id | UUID | PK, default `gen_random_uuid()` |
| user_id | UUID | FK → `users.id`, NOT NULL, `ON DELETE CASCADE` |
| provider | VARCHAR(20) | NOT NULL — e.g. `GOOGLE`, `GITHUB` |
| provider_user_id | VARCHAR(255) | NOT NULL — the `sub` claim / provider's own user id |
| created_at | TIMESTAMPTZ | NOT NULL, default `now()` |

**Constraints:** UNIQUE composite on `(provider, provider_user_id)` — prevents the same external account being linked twice.
**Indexes:** index on `user_id` (lookups when loading a user's linked providers).

---

## oauth_clients
| Column | Type | Constraints |
|---|---|---|
| client_id | VARCHAR(100) | PK |
| client_secret_hash | VARCHAR(255) | NOT NULL — hashed, never stored plaintext |
| client_name | VARCHAR(255) | NOT NULL |
| redirect_uris | TEXT[] | NOT NULL — array of allowed callback URLs |
| scopes | TEXT[] | NOT NULL, default `{'openid','profile','email'}` |
| created_at | TIMESTAMPTZ | NOT NULL, default `now()` |

**Note:** `redirect_uris` must be validated exactly (no wildcard matching) at `/oauth2/authorize` time — this is a standard OAuth2 security requirement, not an implementation detail to skip.

---

## refresh_tokens
| Column | Type | Constraints |
|---|---|---|
| id | UUID | PK, default `gen_random_uuid()` |
| user_id | UUID | FK → `users.id`, NOT NULL, `ON DELETE CASCADE` |
| client_id | VARCHAR(100) | FK → `oauth_clients.client_id`, NOT NULL |
| token_hash | VARCHAR(255) | NOT NULL — SHA-256 hash of the opaque token, never store the raw token |
| expires_at | TIMESTAMPTZ | NOT NULL |
| revoked_at | TIMESTAMPTZ | NULL — set when rotated or explicitly revoked (Decision 5) |
| created_at | TIMESTAMPTZ | NOT NULL, default `now()` |

**Indexes:** UNIQUE index on `token_hash` (lookup on every refresh request — this is the hot path). Index on `user_id` (used for "log out everywhere" / bulk revocation).
**Note:** the raw refresh token is only ever returned to the client once, at issuance — the table stores only its hash, so a database leak alone cannot be used to impersonate a session.

---

## Entity Relationship Summary

```
users (1) ───< (many) linked_accounts
users (1) ───< (many) refresh_tokens
oauth_clients (1) ───< (many) refresh_tokens
```

- A `user` can have multiple `linked_accounts` (Google AND GitHub linked to the same account).
- A `user` can have multiple active `refresh_tokens` (e.g., logged in from more than one client).
- Every `refresh_token` belongs to exactly one `oauth_client` — this scopes revocation and auditing per client application.

## Open Questions Before Finalizing
1. ~~Should `oauth_clients` distinguish confidential vs. public clients?~~ **Resolved:** v1 targets backend/Postman-style clients only (confidential clients). `client_secret_hash` stays `NOT NULL`. Public client support (mobile/SPA, nullable secret) is deferred until a real client of that type is needed.
2. ~~Do we need a `pending_authorizations` table in Postgres?~~ **Resolved:** No — state/PKCE storage is owned entirely by Redis (Decision 7); this table intentionally does not exist in the Postgres schema.
