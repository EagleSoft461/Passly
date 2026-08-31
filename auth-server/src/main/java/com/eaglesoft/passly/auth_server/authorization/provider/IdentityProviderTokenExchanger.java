package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.model.ExternalTokenResponse;

/**
 * Abstraction for exchanging an authorization code for tokens from an external Identity Provider.
 */
public interface IdentityProviderTokenExchanger {

    /**
     * @return The name of the provider this exchanger supports (e.g. "GOOGLE").
     */
    String supports();

    /**
     * Exchanges the authorization code for an external token response.
     *
     * @param code The authorization code received from the provider callback.
     * @return The securely mapped internal representation of the external token response.
     */
    ExternalTokenResponse exchangeCode(String code);
}
