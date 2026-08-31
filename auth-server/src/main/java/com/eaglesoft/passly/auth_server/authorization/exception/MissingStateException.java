package com.eaglesoft.passly.auth_server.authorization.exception;

public class MissingStateException extends OAuthAuthorizationException {
    public MissingStateException(String message) {
        super("invalid_request", message);
    }
}
