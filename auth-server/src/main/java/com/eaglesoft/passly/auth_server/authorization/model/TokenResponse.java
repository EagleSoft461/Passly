package com.eaglesoft.passly.auth_server.authorization.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record TokenResponse(
        @JsonProperty("access_token")
        String accessToken,

        @JsonProperty("token_type")
        String tokenType,

        @JsonProperty("expires_in")
        long expiresIn,

        @JsonProperty("refresh_token")
        String refreshToken
) {
}
