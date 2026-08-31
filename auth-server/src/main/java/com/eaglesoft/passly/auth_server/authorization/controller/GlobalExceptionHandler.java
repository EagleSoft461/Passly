package com.eaglesoft.passly.auth_server.authorization.controller;

import com.eaglesoft.passly.auth_server.authorization.exception.InvalidRedirectUriException;
import com.eaglesoft.passly.auth_server.authorization.exception.OAuthAuthorizationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Maps application-layer authorization exceptions to HTTP responses.
 * Kept separate from the controller (SRP / separation of concerns).
 *
 * Security rule: InvalidRedirectUriException MUST NOT produce a redirect.
 * The redirect_uri supplied by the client is untrusted until validated;
 * returning a 400 with a JSON body is the only safe response.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Invalid redirect_uri: return 400 JSON, no Location header, no redirect.
     * Handled before the generic OAuthAuthorizationException to make the
     * security constraint explicit and impossible to miss in code review.
     */
    @ExceptionHandler(InvalidRedirectUriException.class)
    public ResponseEntity<ErrorResponse> handleInvalidRedirectUri(InvalidRedirectUriException ex) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(ex.getErrorCode(), ex.getMessage()));
    }

    /**
     * All other authorization exceptions (InvalidClientException,
     * MissingStateException, InvalidPkceException, UnsupportedProviderException,
     * UnsupportedResponseTypeException, …).
     * Returns 400 with an OAuth2-style JSON error body. No redirect.
     */
    @ExceptionHandler(OAuthAuthorizationException.class)
    public ResponseEntity<ErrorResponse> handleOAuthAuthorizationException(OAuthAuthorizationException ex) {
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(new ErrorResponse(ex.getErrorCode(), ex.getMessage()));
    }
}
