package com.eaglesoft.passly.auth_server.authorization.controller;

public record CallbackSuccessResponse(
        String status,
        String message,
        String clientId
) {
}
