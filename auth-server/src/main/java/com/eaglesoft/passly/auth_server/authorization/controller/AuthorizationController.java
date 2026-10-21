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
 * Responsibilities:
 * 1. Receive GET /oauth2/authorize.
 * 2. Map query parameters to AuthorizeCommand.
 * 3. Delegate authorization to AuthorizationService.
 * 4. Convert AuthorizationResult into HTTP 302 Found.
 *
 * Validation and business logic belong to the service layer.
 * Error handling is delegated to the global exception handler.
 */
@RestController
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    public AuthorizationController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @GetMapping("/oauth2/authorize")
    public ResponseEntity<Void> authorize(
            @RequestParam("client_id") String clientId,
            @RequestParam("response_type") String responseType,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("state") String state,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("code_challenge_method") String codeChallengeMethod,
            @RequestParam("provider") String provider,
            @RequestParam(value = "scope", required = false) String scope
    ) {
        AuthorizeCommand command = new AuthorizeCommand(
                clientId,
                responseType,
                redirectUri,
                state,
                codeChallenge,
                codeChallengeMethod,
                provider,
                scope
        );

        AuthorizationResult result = authorizationService.authorize(command);

        return ResponseEntity
                .status(302)
                .location(URI.create(result.redirectUrl()))
                .build();
    }
}
