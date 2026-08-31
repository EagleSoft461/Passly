# Local Development Credentials

**⚠️ For local development only. Never use these values in production.**

## Demo OAuth Client (seeded by V2 migration)

- `client_id`: `passly-demo-client`
- `client_secret`: `passly-demo-secret-CHANGE-ME`
- `redirect_uri`: `http://localhost:8080/login/oauth2/code/passly-demo`
- `scopes`: `openid profile email`

The database only stores the BCrypt hash of this secret (see `V2__seed_demo_oauth_client.sql`) — this file is the only place the plaintext value is recorded, for local Postman/curl testing.