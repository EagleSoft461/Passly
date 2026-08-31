package com.eaglesoft.passly.auth_server.authorization.controller;

import com.eaglesoft.passly.auth_server.authorization.model.TokenRequest;
import com.eaglesoft.passly.auth_server.authorization.model.TokenResponse;
import com.eaglesoft.passly.auth_server.authorization.service.TokenService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * HTTP adapter for the OAuth 2.0 token endpoint (RFC 6749 §3.2).
 *
 * Responsibilities (HTTP concerns only):
 *   1. Accept POST /oauth2/token with Content-Type: application/x-www-form-urlencoded
 *      (RFC 6749 §4.1.3 / §6).
 *   2. Bind form parameters → TokenRequest.
 *   3. Delegate business logic (validation, PKCE, JWT issuance, token rotation) to TokenService.
 *   4. On success: return HTTP 200 + JSON TokenResponse + Cache-Control: no-store
 *      (RFC 6749 §5.1).
 *   5. On failure: GlobalExceptionHandler maps OAuthAuthorizationException → 400 JSON error
 *      (RFC 6749 §5.2).
 *
 * This controller must NOT:
 *   - Contain PKCE cryptographic logic.
 *   - Access repositories directly.
 *   - Generate JWTs.
 *   - Implement refresh-token rotation.
 *   - Log any secret parameters (code, code_verifier, refresh_token).
 */
@RestController
public class TokenController {

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    /**
     * POST /oauth2/token
     *
     * Accepts application/x-www-form-urlencoded per RFC 6749 §4.1.3.
     * All parameters are declared optional here because field-level validation
     * (missing required params → error) is the responsibility of TokenService,
     * consistent with the project's layered architecture.
     *
     * Cache-Control: no-store is REQUIRED by RFC 6749 §5.1 to prevent tokens
     * from being stored in caches or browser history.
     */
    @PostMapping(
            value = "/oauth2/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<TokenResponse> token(
            @RequestParam(value = "grant_type",     required = false) String grantType,
            @RequestParam(value = "code",           required = false) String code,
            @RequestParam(value = "redirect_uri",   required = false) String redirectUri,
            @RequestParam(value = "client_id",      required = false) String clientId,
            @RequestParam(value = "code_verifier",  required = false) String codeVerifier,
            @RequestParam(value = "refresh_token",  required = false) String refreshToken
    ) {
        // Build the request value object — no secrets are logged here or in TokenService.
        TokenRequest request = new TokenRequest(
                grantType,
                code,
                redirectUri,
                clientId,
                codeVerifier,
                refreshToken
        );

        TokenResponse response = tokenService.exchange(request);

        // RFC 6749 §5.1 — response MUST include Cache-Control: no-store
        // to prevent caching of credentials in any intermediate cache.
        return ResponseEntity.ok()
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header("Pragma", "no-cache")
                .body(response);
    }
}
