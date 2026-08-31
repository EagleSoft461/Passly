package com.eaglesoft.passly.auth_server.authorization.exception;

/**
 * Thrown when authorization code issuance fails.
 * Generic error to avoid leaking implementation details or sensitive data.
 *
 * Security: Exception message must NOT contain:
 * - Generated authorization code
 * - User ID
 * - Client ID
 * - Technical stack traces (in production)
 */
public class CodeIssuanceException extends OAuthAuthorizationException {
    public CodeIssuanceException(String message) {
        super("server_error", message);
    }
}
