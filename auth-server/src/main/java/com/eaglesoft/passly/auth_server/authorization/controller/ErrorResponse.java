package com.eaglesoft.passly.auth_server.authorization.controller;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Immutable JSON error body returned by GlobalExceptionHandler.
 * Shape follows the OAuth2 error response convention:
 * {"error": "...", "error_description": "..."}.
 */
public record ErrorResponse(
        String error,
        @JsonProperty("error_description") String errorDescription
) {
}
