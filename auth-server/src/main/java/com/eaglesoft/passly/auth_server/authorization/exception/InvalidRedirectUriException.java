package com.eaglesoft.passly.auth_server.authorization.exception;

/**
 * Per docs/api-contract.md: an unregistered redirect_uri must NOT result
 * in a redirect — the URI itself is untrusted at this point. Callers must
 * render an error page instead of redirecting on this exception.
 */
public class InvalidRedirectUriException extends OAuthAuthorizationException {
    public InvalidRedirectUriException(String message) {
        super("invalid_request", message);
    }
}
