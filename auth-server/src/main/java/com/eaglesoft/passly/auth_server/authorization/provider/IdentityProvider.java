package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;

/**
 * Strategy contract for an external identity provider.
 * Each implementation handles one provider (e.g. GOOGLE, GITHUB) and
 * knows how to construct the authorization redirect URL for that provider.
 *
 * AuthorizationService depends on this interface, never on concrete classes.
 */
public interface IdentityProvider {

    /**
     * Returns the provider name this implementation handles.
     * Must match the values of {@link com.eaglesoft.passly.auth_server.domain.LinkedAccount.Provider}
     * (e.g. "GOOGLE", "GITHUB").
     */
    String supports();

    /**
     * Builds the authorization URL to redirect the user's browser to the
     * external identity provider.
     *
     * @param request the persisted authorization request containing state,
     *                PKCE, clientId, redirectUri, and provider
     * @return the fully-constructed authorization URL for this provider
     */
    String buildAuthorizationUrl(AuthorizationRequest request);
}
