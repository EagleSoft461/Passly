package com.eaglesoft.passly.auth_server.authorization.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public record ExternalTokenResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("expires_in") Integer expiresIn,
        @JsonProperty("id_token") String idToken,
        @JsonProperty("scope") String scope,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("refresh_token") String refreshToken
) {
}
