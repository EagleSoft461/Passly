package com.eaglesoft.passly.auth_server.authorization.exception;

/**
 * Thrown when attempting to link an account with an unverified email.
 * Security requirement: email_verified must be true to prevent account takeover attacks.
 */
public class UnverifiedEmailException extends OAuthAuthorizationException {
    public UnverifiedEmailException(String message) {
        super("unverified_email", message);
    }
}
