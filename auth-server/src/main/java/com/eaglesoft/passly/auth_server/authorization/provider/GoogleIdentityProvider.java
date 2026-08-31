package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * Implementation of {@link IdentityProvider} for Google.
 * Constructs the Google OAuth2 authorization URL using the configured
 * client ID, redirect URI, scopes, and the state and PKCE challenge
 * from the existing authorization request.
 */
@Component
public class GoogleIdentityProvider implements IdentityProvider {

    private static final String GOOGLE_AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";

    private final GoogleOAuthProperties properties;

    public GoogleIdentityProvider(GoogleOAuthProperties properties) {
        this.properties = properties;
    }

    @Override
    public String supports() {
        return "GOOGLE";
    }

    @Override
    public String buildAuthorizationUrl(AuthorizationRequest request) {
        return UriComponentsBuilder.fromUriString(GOOGLE_AUTHORIZATION_ENDPOINT)
                .queryParam("response_type", "code")
                .queryParam("client_id", properties.clientId())
                .queryParam("redirect_uri", properties.redirectUri())
                .queryParam("scope", properties.scopes())
                .queryParam("state", request.state())
                .queryParam("code_challenge", request.codeChallenge())
                .queryParam("code_challenge_method", request.codeChallengeMethod())
                .build()
                .encode()
                .toUriString();
    }
}
