package com.eaglesoft.passly.auth_server.authorization.model;

public record TokenRequest(
        String grantType,
        String code,
        String redirectUri,
        String clientId,
        String codeVerifier,
        String refreshToken
) {
}
