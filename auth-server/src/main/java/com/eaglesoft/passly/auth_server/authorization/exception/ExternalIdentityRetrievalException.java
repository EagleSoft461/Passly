package com.eaglesoft.passly.auth_server.authorization.exception;

/**
 * Thrown when external user info retrieval fails.
 * This indicates a problem communicating with the external identity provider's UserInfo endpoint.
 */
public class ExternalIdentityRetrievalException extends OAuthAuthorizationException {
    public ExternalIdentityRetrievalException(String message) {
        super("server_error", message);
    }
}
