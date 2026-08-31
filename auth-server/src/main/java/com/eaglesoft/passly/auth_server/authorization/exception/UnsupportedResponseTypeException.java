package com.eaglesoft.passly.auth_server.authorization.exception;

public class UnsupportedResponseTypeException extends OAuthAuthorizationException {
    public UnsupportedResponseTypeException(String message) {
        super("unsupported_response_type", message);
    }
}
