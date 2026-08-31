package com.eaglesoft.passly.auth_server.authorization.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * External identity provider user information.
 * Contains the stable identifier (sub), email, and profile data.
 * This represents the UserInfo response from providers like Google/GitHub.
 */
public record ExternalUserInfo(
        String sub,
        String email,
        @JsonProperty("email_verified") Boolean emailVerified,
        String name,
        String picture
) {
    public ExternalUserInfo {
        if (sub == null || sub.isBlank()) {
            throw new IllegalArgumentException("sub cannot be null or blank");
        }
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email cannot be null or blank");
        }
    }
}
