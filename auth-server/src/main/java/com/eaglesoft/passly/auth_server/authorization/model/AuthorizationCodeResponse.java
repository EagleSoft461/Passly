package com.eaglesoft.passly.auth_server.authorization.model;

/**
 * Response from callback service after authorization code issuance.
 * Contains all information needed for HTTP redirect to client.
 */
public record AuthorizationCodeResponse(
        String authorizationCode,
        String redirectUri,
        String originalState
) {
    public AuthorizationCodeResponse {
        if (authorizationCode == null || authorizationCode.isBlank()) {
            throw new IllegalArgumentException("authorizationCode cannot be null or blank");
        }
        if (redirectUri == null || redirectUri.isBlank()) {
            throw new IllegalArgumentException("redirectUri cannot be null or blank");
        }
        if (originalState == null || originalState.isBlank()) {
            throw new IllegalArgumentException("originalState cannot be null or blank");
        }
    }
}
