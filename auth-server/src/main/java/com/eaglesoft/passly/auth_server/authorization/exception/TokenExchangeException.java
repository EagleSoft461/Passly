package com.eaglesoft.passly.auth_server.authorization.exception;

public class TokenExchangeException extends OAuthAuthorizationException {
    public TokenExchangeException(String message) {
        super("invalid_grant", message);
    }

    public TokenExchangeException(String errorCode, String message) {
        super(errorCode, message);
    }
}
