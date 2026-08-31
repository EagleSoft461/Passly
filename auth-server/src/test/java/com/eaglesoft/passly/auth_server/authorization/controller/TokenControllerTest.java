package com.eaglesoft.passly.auth_server.authorization.controller;

import com.eaglesoft.passly.auth_server.authorization.exception.TokenExchangeException;
import com.eaglesoft.passly.auth_server.authorization.model.TokenRequest;
import com.eaglesoft.passly.auth_server.authorization.model.TokenResponse;
import com.eaglesoft.passly.auth_server.authorization.service.TokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Controller-layer tests for POST /oauth2/token using MockMvc standaloneSetup.
 *
 * Test conventions (identical to AuthorizationControllerTest):
 *   - No Spring Boot context, no DB, no Redis.
 *   - TokenService is mocked; only HTTP binding and response shaping are tested.
 *   - GlobalExceptionHandler is registered explicitly so exception-to-HTTP mapping is covered.
 *   - No security filter chain is active (standaloneSetup bypasses security).
 *
 * RFC compliance notes:
 *   - HTTP 200 + Cache-Control: no-store on success  (RFC 6749 §5.1)
 *   - HTTP 400 + JSON error body on failure           (RFC 6749 §5.2)
 *
 * NOTE: Tests that verify error bodies assert "server_error" because that is the
 * pre-existing error code produced by TokenExchangeException (see implementation_plan.md
 * Conflict 1). The tests document actual current behavior, not claimed RFC compliance.
 */
@ExtendWith(MockitoExtension.class)
class TokenControllerTest {

    private static final String ENDPOINT = "/oauth2/token";

    // Shared constants — realistic but non-sensitive test values
    private static final String CLIENT_ID      = "passly-demo-client";
    private static final String REDIRECT_URI   = "http://localhost:8080/login/oauth2/code/passly-demo";
    private static final String AUTH_CODE      = "test-auth-code-abc";
    private static final String CODE_VERIFIER  = "test-code-verifier-xyz";
    private static final String REFRESH_TOKEN  = "test-refresh-token-rot";

    private static final TokenResponse STUB_RESPONSE = new TokenResponse(
            "eyJhbGciOiJSUzI1NiJ9.stub.sig",
            "Bearer",
            900L,
            "new-refresh-token-abc"
    );

    @Mock
    private TokenService tokenService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(new TokenController(tokenService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    // ---------------------------------------------------------------
    // Helper: build a valid authorization_code form POST
    // ---------------------------------------------------------------
    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder validAuthCodeRequest() {
        return post(ENDPOINT)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type",    "authorization_code")
                .param("code",          AUTH_CODE)
                .param("redirect_uri",  REDIRECT_URI)
                .param("client_id",     CLIENT_ID)
                .param("code_verifier", CODE_VERIFIER);
    }

    // ---------------------------------------------------------------
    // 1. Valid authorization_code exchange
    //    RFC 6749 §4.1.3 + §5.1
    // ---------------------------------------------------------------
    @Test
    void validAuthorizationCode_returns200WithTokenResponseAndNoCacheHeader() throws Exception {
        when(tokenService.exchange(any())).thenReturn(STUB_RESPONSE);

        mockMvc.perform(validAuthCodeRequest())
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                // RFC 6749 §5.1 — must include Cache-Control: no-store
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.access_token").value(STUB_RESPONSE.accessToken()))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andExpect(jsonPath("$.refresh_token").value(STUB_RESPONSE.refreshToken()));

        verify(tokenService).exchange(any());
    }

    // ---------------------------------------------------------------
    // 2. Missing grant_type → service throws, 400 JSON error
    // ---------------------------------------------------------------
    // 2. Missing grant_type → service throws, 400 JSON error
    //    RFC 6749 §5.2 — invalid_request
    // ---------------------------------------------------------------
    @Test
    void missingGrantType_returns400JsonError() throws Exception {
        when(tokenService.exchange(any()))
                .thenThrow(new TokenExchangeException("invalid_request", "grant_type is required"));

        mockMvc.perform(post(ENDPOINT)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("code",          AUTH_CODE)
                        .param("redirect_uri",  REDIRECT_URI)
                        .param("client_id",     CLIENT_ID)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("grant_type is required"));
    }

    // ---------------------------------------------------------------
    // 3. Unsupported grant_type → service throws, 400 JSON error
    //    RFC 6749 §5.2 — unsupported_grant_type
    // ---------------------------------------------------------------
    @Test
    void unsupportedGrantType_returns400JsonError() throws Exception {
        when(tokenService.exchange(any()))
                .thenThrow(new TokenExchangeException("unsupported_grant_type", "Unsupported grant_type: implicit"));

        mockMvc.perform(post(ENDPOINT)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "implicit")
                        .param("code",          AUTH_CODE)
                        .param("redirect_uri",  REDIRECT_URI)
                        .param("client_id",     CLIENT_ID)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"))
                .andExpect(jsonPath("$.error_description").value("Unsupported grant_type: implicit"));
    }

    // ---------------------------------------------------------------
    // 4. Missing code → service throws, 400 JSON error
    //    RFC 6749 §5.2 — invalid_request
    // ---------------------------------------------------------------
    @Test
    void missingCode_returns400JsonError() throws Exception {
        when(tokenService.exchange(any()))
                .thenThrow(new TokenExchangeException("invalid_request", "code is required"));

        mockMvc.perform(post(ENDPOINT)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "authorization_code")
                        .param("redirect_uri",  REDIRECT_URI)
                        .param("client_id",     CLIENT_ID)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("code is required"));
    }

    // ---------------------------------------------------------------
    // 5. Missing client_id → service throws, 400 JSON error
    //    RFC 6749 §5.2 — invalid_request
    // ---------------------------------------------------------------
    @Test
    void missingClientId_returns400JsonError() throws Exception {
        when(tokenService.exchange(any()))
                .thenThrow(new TokenExchangeException("invalid_request", "client_id is required"));

        mockMvc.perform(post(ENDPOINT)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "authorization_code")
                        .param("code",          AUTH_CODE)
                        .param("redirect_uri",  REDIRECT_URI)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("client_id is required"));
    }

    // ---------------------------------------------------------------
    // 6. Missing redirect_uri → service throws, 400 JSON error
    //    RFC 6749 §5.2 — invalid_request
    // ---------------------------------------------------------------
    @Test
    void missingRedirectUri_returns400JsonError() throws Exception {
        when(tokenService.exchange(any()))
                .thenThrow(new TokenExchangeException("invalid_request", "redirect_uri is required"));

        mockMvc.perform(post(ENDPOINT)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "authorization_code")
                        .param("code",          AUTH_CODE)
                        .param("client_id",     CLIENT_ID)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("redirect_uri is required"));
    }

    // ---------------------------------------------------------------
    // 7. Missing code_verifier → service throws, 400 JSON error
    //    RFC 7636 §4.6 — PKCE verification is mandatory
    // ---------------------------------------------------------------
    @Test
    void missingCodeVerifier_returns400JsonError() throws Exception {
        when(tokenService.exchange(any()))
                .thenThrow(new TokenExchangeException("invalid_request", "code_verifier is required"));

        mockMvc.perform(post(ENDPOINT)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",   "authorization_code")
                        .param("code",         AUTH_CODE)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id",    CLIENT_ID))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("code_verifier is required"));
    }

    // ---------------------------------------------------------------
    // 8. Invalid authorization code → service throws, 400 JSON error
    //    RFC 6749 §5.2 — invalid_grant
    // ---------------------------------------------------------------
    @Test
    void invalidAuthorizationCode_returns400JsonError() throws Exception {
        when(tokenService.exchange(any()))
                .thenThrow(new TokenExchangeException("invalid_grant", "Invalid or expired authorization code"));

        mockMvc.perform(validAuthCodeRequest())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.error_description").value("Invalid or expired authorization code"));
    }

    // ---------------------------------------------------------------
    // 9. Authorization code / client mismatch → service throws, 400 JSON error
    //    RFC 6749 §5.2 — invalid_grant
    // ---------------------------------------------------------------
    @Test
    void authorizationCodeClientMismatch_returns400JsonError() throws Exception {
        when(tokenService.exchange(any()))
                .thenThrow(new TokenExchangeException("invalid_grant", "Authorization code does not belong to client"));

        mockMvc.perform(validAuthCodeRequest())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.error_description").value("Authorization code does not belong to client"));
    }

    // ---------------------------------------------------------------
    // 10. redirect_uri mismatch → service throws, 400 JSON error
    //     RFC 6749 §4.1.3 + §5.2 — redirect_uri must match authorization request
    // ---------------------------------------------------------------
    @Test
    void redirectUriMismatch_returns400JsonError() throws Exception {
        when(tokenService.exchange(any()))
                .thenThrow(new TokenExchangeException("invalid_grant", "redirect_uri does not match authorization request"));

        mockMvc.perform(post(ENDPOINT)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "authorization_code")
                        .param("code",          AUTH_CODE)
                        .param("redirect_uri",  "http://evil.example.com/callback")
                        .param("client_id",     CLIENT_ID)
                        .param("code_verifier", CODE_VERIFIER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.error_description").value("redirect_uri does not match authorization request"));
    }

    // ---------------------------------------------------------------
    // 11. Invalid PKCE verifier → service throws, 400 JSON error
    //     RFC 7636 §4.6 — S256 hash must match stored code_challenge
    // ---------------------------------------------------------------
    @Test
    void invalidPkceVerifier_returns400JsonError() throws Exception {
        when(tokenService.exchange(any()))
                .thenThrow(new TokenExchangeException("invalid_grant", "Invalid code_verifier"));

        mockMvc.perform(post(ENDPOINT)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "authorization_code")
                        .param("code",          AUTH_CODE)
                        .param("redirect_uri",  REDIRECT_URI)
                        .param("client_id",     CLIENT_ID)
                        .param("code_verifier", "wrong-verifier"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_grant"))
                .andExpect(jsonPath("$.error_description").value("Invalid code_verifier"));
    }

    // ---------------------------------------------------------------
    // 12. Valid refresh_token exchange
    //     RFC 6749 §6 + §5.1
    // ---------------------------------------------------------------
    @Test
    void validRefreshToken_returns200WithNewTokenResponse() throws Exception {
        TokenResponse rotatedResponse = new TokenResponse(
                "eyJhbGciOiJSUzI1NiJ9.rotated.sig",
                "Bearer",
                900L,
                "rotated-refresh-token-def"
        );
        when(tokenService.exchange(any())).thenReturn(rotatedResponse);

        mockMvc.perform(post(ENDPOINT)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "refresh_token")
                        .param("refresh_token", REFRESH_TOKEN)
                        .param("client_id",     CLIENT_ID))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.access_token").value(rotatedResponse.accessToken()))
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").value(900))
                .andExpect(jsonPath("$.refresh_token").value(rotatedResponse.refreshToken()));

        verify(tokenService).exchange(any());
    }

    // ---------------------------------------------------------------
    // 13. Form parameters are correctly mapped to TokenRequest
    //     Verifies the HTTP → domain boundary mapping is correct.
    // ---------------------------------------------------------------
    @Test
    void formParametersAreMappedToTokenRequestCorrectly() throws Exception {
        when(tokenService.exchange(any())).thenReturn(STUB_RESPONSE);

        mockMvc.perform(validAuthCodeRequest());

        ArgumentCaptor<TokenRequest> captor = ArgumentCaptor.forClass(TokenRequest.class);
        verify(tokenService).exchange(captor.capture());

        TokenRequest captured = captor.getValue();
        assertThat(captured.grantType()).isEqualTo("authorization_code");
        assertThat(captured.code()).isEqualTo(AUTH_CODE);
        assertThat(captured.redirectUri()).isEqualTo(REDIRECT_URI);
        assertThat(captured.clientId()).isEqualTo(CLIENT_ID);
        assertThat(captured.codeVerifier()).isEqualTo(CODE_VERIFIER);
        assertThat(captured.refreshToken()).isNull();
    }
}
