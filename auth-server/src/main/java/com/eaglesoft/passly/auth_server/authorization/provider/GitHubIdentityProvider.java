package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import org.springframework.stereotype.Component;

/**
 * Structural implementation of {@link IdentityProvider} for GitHub.
 *
 * NOT YET IMPLEMENTED (Roadmap Phase 2):
 * This class registers the GitHub provider in the system so that the
 * authorization flow can resolve it, but it does not yet construct a real
 * GitHub OAuth2 authorization URL. Any attempt to invoke
 * {@link #buildAuthorizationUrl} will throw {@link UnsupportedOperationException}
 * to prevent accidental use in production.
 *
 * Intended future implementation: build the GitHub OAuth2 authorization URL
 * using the configured client ID, redirect URI, scopes, state and PKCE
 * code challenge.
 */
@Component
public class GitHubIdentityProvider implements IdentityProvider {

    @Override
    public String supports() {
        return "GITHUB";
    }

    /**
     * @throws UnsupportedOperationException always — GitHub OAuth2 URL
     *         construction is not yet implemented (Roadmap Phase 2).
     */
    @Override
    public String buildAuthorizationUrl(AuthorizationRequest request) {
        throw new UnsupportedOperationException(
                "GitHub OAuth2 authorization URL construction is not yet implemented (Roadmap Phase 2)");
    }
}
