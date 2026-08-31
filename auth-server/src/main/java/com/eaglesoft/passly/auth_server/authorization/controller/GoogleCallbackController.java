package com.eaglesoft.passly.auth_server.authorization.controller;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationCodeResponse;
import com.eaglesoft.passly.auth_server.authorization.service.GoogleCallbackService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@RestController
public class GoogleCallbackController {

    private final GoogleCallbackService googleCallbackService;

    public GoogleCallbackController(GoogleCallbackService googleCallbackService) {
        this.googleCallbackService = googleCallbackService;
    }

    @GetMapping("/login/oauth2/code/google")
    public ResponseEntity<Void> googleCallback(
            @RequestParam(required = false) String code,
            @RequestParam(required = false) String state) {

        AuthorizationCodeResponse response = googleCallbackService.handleCallback(code, state);

        // Build redirect URL with authorization code and state
        // Uses validated redirect_uri from AuthorizationRequest (never from callback request)
        URI redirectUri = UriComponentsBuilder
                .fromUriString(response.redirectUri())
                .queryParam("code", response.authorizationCode())
                .queryParam("state", response.originalState())
                .build()
                .toUri();

        // HTTP 302 redirect to client with authorization code
        return ResponseEntity.status(HttpStatus.FOUND)
                .location(redirectUri)
                .build();
    }
}
