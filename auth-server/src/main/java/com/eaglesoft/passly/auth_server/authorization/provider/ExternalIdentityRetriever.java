package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.model.ExternalUserInfo;

/**
 * Retrieves user identity information from an external OAuth provider.
 * Implementations call the provider's UserInfo endpoint using the access token.
 */
public interface ExternalIdentityRetriever {

    /**
     * @return The provider this retriever supports (e.g., "GOOGLE")
     */
    String supports();

    /**
     * Retrieves user information from the provider using the access token.
     *
     * @param accessToken The access token from the token exchange response
     * @return External user information including stable subject ID
     * @throws com.eaglesoft.passly.auth_server.authorization.exception.ExternalIdentityRetrievalException if retrieval fails
     */
    ExternalUserInfo retrieveUserInfo(String accessToken);
}
