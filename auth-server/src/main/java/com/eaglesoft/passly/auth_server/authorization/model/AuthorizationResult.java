package com.eaglesoft.passly.auth_server.authorization.model;

/**
 * Output of AuthorizationService.authorize(). The controller turns this
 * into an HTTP 302 redirect — it does not build the URL itself.
 */
public record AuthorizationResult(
        String state,
        String redirectUrl
) {
}
