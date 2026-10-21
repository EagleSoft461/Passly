package com.eaglesoft.passly.auth_server.authorization.exception;

public class InvalidScopeException extends OAuthAuthorizationException {
    public InvalidScopeException(String message) {
        super("invalid_scope", message);
    }
}
