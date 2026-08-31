package com.eaglesoft.passly.auth_server.authorization.controller;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationResult;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizeCommand;
import com.eaglesoft.passly.auth_server.authorization.service.AuthorizationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

/**
 * HTTP adapter for the OAuth2 authorization endpoint.
 *
 * Responsibilities (HTTP concerns only):
 *   1. Receive GET /oauth2/authorize
 *   2. Map query parameters → AuthorizeCommand
 *   3. Delegate to AuthorizationService
 *   4. Convert AuthorizationResult into HTTP 302 Found
 *
 * All validation, business logic, and error semantics live in the
 * service layer and GlobalExceptionHandler respectively.
 */
@RestController
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    public AuthorizationController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @GetMapping("/oauth2/authorize")
    public ResponseEntity<Void> authorize(
            @RequestParam("client_id")             String clientId,
            @RequestParam("response_type")         String responseType,
            @RequestParam("redirect_uri")          String redirectUri,
            @RequestParam("state")                 String state,
            @RequestParam("code_challenge")        String codeChallenge,
            @RequestParam("code_challenge_method") String codeChallengeMethod,
            @RequestParam("provider")              String provider
    ) {
        AuthorizeCommand command = new AuthorizeCommand(
                clientId,
                responseType,
                redirectUri,
                state,
                codeChallenge,
                codeChallengeMethod,
                provider
        );

        AuthorizationResult result = authorizationService.authorize(command);

        return ResponseEntity
                .status(302)
                .location(URI.create(result.redirectUrl()))
                .build();
    }
}
