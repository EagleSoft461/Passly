package com.eaglesoft.passly.auth_server.authorization.exception;

/**
 * Base type for authorization-request errors. errorCode matches the
 * OAuth2 error codes documented in docs/api-contract.md.
 */
public abstract class OAuthAuthorizationException extends RuntimeException {

    private final String errorCode;

    protected OAuthAuthorizationException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
