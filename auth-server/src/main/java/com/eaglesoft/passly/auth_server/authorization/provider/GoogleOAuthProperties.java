package com.eaglesoft.passly.auth_server.authorization.provider;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "passly.oauth.google")
public record GoogleOAuthProperties(
        String clientId,
        String clientSecret,
        String redirectUri,
        String scopes
) {
    public GoogleOAuthProperties {
        if (scopes == null || scopes.isBlank()) {
            scopes = "openid email profile";
        }
    }
}
