package com.eaglesoft.passly.auth_server.authorization.model;

import java.time.Instant;

public record AuthorizationRequest(
        String state,
        String clientId,
        String redirectUri,
        String codeChallenge,
        String codeChallengeMethod,
        String provider,
        Instant expiresAt
) {
}
