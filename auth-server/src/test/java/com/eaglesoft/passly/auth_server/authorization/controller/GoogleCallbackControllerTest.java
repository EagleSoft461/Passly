package com.eaglesoft.passly.auth_server.authorization.controller;

import com.eaglesoft.passly.auth_server.authorization.exception.InvalidStateException;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationCodeResponse;
import com.eaglesoft.passly.auth_server.authorization.service.GoogleCallbackService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@ExtendWith(MockitoExtension.class)
class GoogleCallbackControllerTest {

    private MockMvc mockMvc;

    @Mock
    private GoogleCallbackService googleCallbackService;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(new GoogleCallbackController(googleCallbackService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    @Test
    void shouldRedirectWithAuthorizationCode() throws Exception {
        AuthorizationCodeResponse response = new AuthorizationCodeResponse(
                "passly-code-abc123",
                "https://client.example.com/callback",
                "original-state-xyz"
        );

        when(googleCallbackService.handleCallback("google-code-456", "original-state-xyz"))
                .thenReturn(response);

        mockMvc.perform(get("/login/oauth2/code/google")
                        .param("code", "google-code-456")
                        .param("state", "original-state-xyz"))
                .andExpect(status().isFound())  // HTTP 302
                .andExpect(header().string("Location",
                        "https://client.example.com/callback?code=passly-code-abc123&state=original-state-xyz"));
    }

    @Test
    void shouldHandleRedirectUriWithExistingQueryParameters() throws Exception {
        AuthorizationCodeResponse response = new AuthorizationCodeResponse(
                "auth-code-xyz",
                "https://app.com/auth?session=abc",
                "state-123"
        );

        when(googleCallbackService.handleCallback("google-code", "state-123"))
                .thenReturn(response);

        mockMvc.perform(get("/login/oauth2/code/google")
                        .param("code", "google-code")
                        .param("state", "state-123"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location",
                        "https://app.com/auth?session=abc&code=auth-code-xyz&state=state-123"));
    }

    @Test
    void shouldReturn400BadRequestWhenStateIsInvalid() throws Exception {
        when(googleCallbackService.handleCallback("code-xyz", "invalid-state"))
                .thenThrow(new InvalidStateException("Invalid, expired, or already consumed state"));

        mockMvc.perform(get("/login/oauth2/code/google")
                        .param("code", "code-xyz")
                        .param("state", "invalid-state"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("Invalid, expired, or already consumed state"));
    }

    @Test
    void shouldReturn400BadRequestWhenMissingParameters() throws Exception {
        when(googleCallbackService.handleCallback(null, null))
                .thenThrow(new InvalidStateException("Missing state parameter"));

        mockMvc.perform(get("/login/oauth2/code/google"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value("Missing state parameter"));
    }

    @Test
    void shouldNotExposeAuthorizationCodeInErrorResponse() throws Exception {
        when(googleCallbackService.handleCallback("google-code", "bad-state"))
                .thenThrow(new InvalidStateException("State validation failed"));

        mockMvc.perform(get("/login/oauth2/code/google")
                        .param("code", "google-code")
                        .param("state", "bad-state"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error_description").value("State validation failed"))
                .andExpect(content().string(org.hamcrest.Matchers.not(
                        org.hamcrest.Matchers.containsString("google-code"))));
    }

    @Test
    void shouldPreserveStateInRedirect() throws Exception {
        AuthorizationCodeResponse response = new AuthorizationCodeResponse(
                "new-auth-code",
                "https://app.com/callback",
                "preserved-state-value"
        );

        when(googleCallbackService.handleCallback("code", "preserved-state-value"))
                .thenReturn(response);

        mockMvc.perform(get("/login/oauth2/code/google")
                        .param("code", "code")
                        .param("state", "preserved-state-value"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location",
                        org.hamcrest.Matchers.containsString("state=preserved-state-value")));
    }
}
