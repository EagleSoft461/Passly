package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.domain.OAuthClient;

public interface OAuthClientService {

    /**
     * Validates that the client exists, is enabled, and that redirectUri
     * is one of its exactly-registered URIs.
     *
     * @throws com.eaglesoft.passly.auth_server.authorization.exception.InvalidClientException
     *         if the client does not exist or is disabled
     * @throws com.eaglesoft.passly.auth_server.authorization.exception.InvalidRedirectUriException
     *         if redirectUri is not registered for this client
     */
    OAuthClient validateClientAndRedirectUri(String clientId, String redirectUri);
}
