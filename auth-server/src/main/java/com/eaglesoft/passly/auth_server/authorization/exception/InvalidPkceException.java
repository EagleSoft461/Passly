package com.eaglesoft.passly.auth_server.authorization.exception;

public class InvalidPkceException extends OAuthAuthorizationException {
    public InvalidPkceException(String message) {
        super("invalid_request", message);
    }
}
