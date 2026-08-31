package com.eaglesoft.passly.auth_server.authorization.security;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksController {

    private final JwksService jwksService;

    public JwksController(JwksService jwksService) {
        this.jwksService = jwksService;
    }

    @GetMapping(
            value = "/.well-known/jwks.json",
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<String> jwks() {
        return ResponseEntity.ok(jwksService.getJwks());
    }
}
