-- V1__init_schema.sql
-- Passly initial schema — see docs/entity-design.md for full column rationale

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           VARCHAR(255) NOT NULL UNIQUE,
    email_verified  BOOLEAN NOT NULL DEFAULT false,
    display_name    VARCHAR(255),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE linked_accounts (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id           UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider          VARCHAR(20) NOT NULL,
    provider_user_id  VARCHAR(255) NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_linked_accounts_provider_user UNIQUE (provider, provider_user_id)
);

CREATE INDEX idx_linked_accounts_user_id ON linked_accounts(user_id);

CREATE TABLE oauth_clients (
    client_id           VARCHAR(100) PRIMARY KEY,
    client_secret_hash  VARCHAR(255) NOT NULL,
    client_name         VARCHAR(255) NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE oauth_client_redirect_uris (
    client_id     VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    redirect_uri  TEXT NOT NULL
);

CREATE TABLE oauth_client_scopes (
    client_id  VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    scope      VARCHAR(100) NOT NULL
);

CREATE TABLE refresh_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id    VARCHAR(100) NOT NULL REFERENCES oauth_clients(client_id),
    token_hash   VARCHAR(255) NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
