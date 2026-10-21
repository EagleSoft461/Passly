package com.eaglesoft.passly.auth_server.authorization.model;

import java.time.Instant;
import java.util.UUID;

/**
 * Represents a Passly authorization code issued after successful external authentication.
 * Stored in Redis with short TTL for single-use consumption.
 *
 * Security:
 * - Code is plaintext (not hashed) since it's short-lived (2 minutes) and single-use
 * - TTL ensures automatic cleanup
 * - Single-use enforced via Redis getAndDelete() atomic operation
 * - Contains PKCE challenge for later verification at /oauth2/token
 */
public record PasslyAuthorizationCode(
        String code,
        UUID userId,
        String clientId,
        String redirectUri,
        String codeChallenge,
        String codeChallengeMethod,
        String scope,
        Instant createdAt,
        Instant expiresAt
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

    public PasslyAuthorizationCode(
            String code,
            UUID userId,
            String clientId,
            String redirectUri,
            String codeChallenge,
            String codeChallengeMethod,
            Instant createdAt,
            Instant expiresAt
    ) {
        this(code, userId, clientId, redirectUri, codeChallenge, codeChallengeMethod, null, createdAt, expiresAt);
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
