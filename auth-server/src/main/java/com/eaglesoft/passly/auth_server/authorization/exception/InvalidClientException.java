package com.eaglesoft.passly.auth_server.authorization.exception;

public class InvalidClientException extends OAuthAuthorizationException {
    public InvalidClientException(String message) {
        super("invalid_client", message);
    }
}
