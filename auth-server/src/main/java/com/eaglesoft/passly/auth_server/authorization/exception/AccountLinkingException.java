package com.eaglesoft.passly.auth_server.authorization.exception;

/**
 * Thrown when account linking fails due to database constraints or business rule violations.
 * This wraps persistence-level exceptions into a meaningful domain exception.
 */
public class AccountLinkingException extends OAuthAuthorizationException {
    public AccountLinkingException(String message) {
        super("account_linking_failed", message);
    }
}
