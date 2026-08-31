package com.eaglesoft.passly.auth_server.authorization.exception;

public class InvalidStateException extends OAuthAuthorizationException {
    public InvalidStateException(String message) {
        super("invalid_request", message);
    }
}
