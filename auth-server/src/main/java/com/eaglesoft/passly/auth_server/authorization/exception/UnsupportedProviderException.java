package com.eaglesoft.passly.auth_server.authorization.exception;

public class UnsupportedProviderException extends OAuthAuthorizationException {
    public UnsupportedProviderException(String message) {
        super("invalid_request", message);
    }
}
