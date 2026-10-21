package com.eaglesoft.passly.auth_server.authorization.model;

import java.time.Instant;

public record AuthorizationRequest(
        String state,
        String clientId,
        String redirectUri,
        String codeChallenge,
        String codeChallengeMethod,
        String provider,
        String scope,
        Instant expiresAt
) {
    public AuthorizationRequest(
            String state,
            String clientId,
            String redirectUri,
            String codeChallenge,
            String codeChallengeMethod,
            String provider,
            Instant expiresAt
    ) {
        this(state, clientId, redirectUri, codeChallenge, codeChallengeMethod, provider, null, expiresAt);
    }
}
