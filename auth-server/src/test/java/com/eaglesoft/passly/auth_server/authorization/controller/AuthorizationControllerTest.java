package com.eaglesoft.passly.auth_server.authorization.controller;

import com.eaglesoft.passly.auth_server.authorization.exception.InvalidClientException;
import com.eaglesoft.passly.auth_server.authorization.exception.InvalidPkceException;
import com.eaglesoft.passly.auth_server.authorization.exception.InvalidRedirectUriException;
import com.eaglesoft.passly.auth_server.authorization.exception.MissingStateException;
import com.eaglesoft.passly.auth_server.authorization.exception.UnsupportedProviderException;
import com.eaglesoft.passly.auth_server.authorization.exception.UnsupportedResponseTypeException;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationResult;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizeCommand;
import com.eaglesoft.passly.auth_server.authorization.service.AuthorizationService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Controller-layer tests using MockMvc standaloneSetup.
 *
 * No Spring Boot context, no real DB or Redis required.
 * GlobalExceptionHandler is registered explicitly so exception
 * mapping is covered without needing @WebMvcTest autoconfiguration.
 * No security filter chain is active — this tests the controller
 * and advice in isolation.
 */
@ExtendWith(MockitoExtension.class)
class AuthorizationControllerTest {

    private static final String ENDPOINT = "/oauth2/authorize";

    private static final String CLIENT_ID    = "passly-demo-client";
    private static final String REDIRECT_URI = "http://localhost:8080/login/oauth2/code/passly-demo";
    private static final String STATE        = "client-state-abc";
    private static final String CHALLENGE    = "challenge-xyz";
    private static final String METHOD       = "S256";
    private static final String PROVIDER     = "GOOGLE";
    private static final String REDIRECT_URL =
            "https://accounts.google.com/o/oauth2/v2/auth?state=client-state-abc";

    @Mock
    private AuthorizationService authorizationService;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(new AuthorizationController(authorizationService))
                .setControllerAdvice(new GlobalExceptionHandler())
                .build();
    }

    // ---------------------------------------------------------------
    // Helper: build a GET request with all valid params
    // ---------------------------------------------------------------
    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder validRequest() {
        return get(ENDPOINT)
                .param("client_id",             CLIENT_ID)
                .param("response_type",         "code")
                .param("redirect_uri",          REDIRECT_URI)
                .param("state",                 STATE)
                .param("code_challenge",        CHALLENGE)
                .param("code_challenge_method", METHOD)
                .param("provider",              PROVIDER);
    }

    // ---------------------------------------------------------------
    // 1. Valid request → AuthorizationService called, 302, Location header
    // ---------------------------------------------------------------
    @Test
    void validRequest_callsService_returns302WithLocationHeader() throws Exception {
        when(authorizationService.authorize(any()))
                .thenReturn(new AuthorizationResult(STATE, REDIRECT_URL));

        mockMvc.perform(validRequest())
                .andExpect(status().isFound())
                .andExpect(header().string("Location", REDIRECT_URL));

        verify(authorizationService).authorize(any());
    }

    // ---------------------------------------------------------------
    // 2. Invalid client → 400, JSON error, no Location header
    // ---------------------------------------------------------------
    @Test
    void invalidClient_returns400JsonError_noLocationHeader() throws Exception {
        when(authorizationService.authorize(any()))
                .thenThrow(new InvalidClientException("unknown client"));

        mockMvc.perform(validRequest())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"))
                .andExpect(jsonPath("$.error_description").value("unknown client"))
                .andExpect(header().doesNotExist("Location"));
    }

    // ---------------------------------------------------------------
    // 3. Invalid redirect_uri → 400, no Location, absolutely NO redirect
    // ---------------------------------------------------------------
    @Test
    void invalidRedirectUri_returns400_noRedirectEver() throws Exception {
        when(authorizationService.authorize(any()))
                .thenThrow(new InvalidRedirectUriException("redirect_uri mismatch"));

        mockMvc.perform(validRequest())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(header().doesNotExist("Location"));
    }

    // ---------------------------------------------------------------
    // 4. Invalid PKCE → 400, JSON OAuth error
    // ---------------------------------------------------------------
    @Test
    void invalidPkce_returns400JsonError() throws Exception {
        when(authorizationService.authorize(any()))
                .thenThrow(new InvalidPkceException("code_challenge is required"));

        mockMvc.perform(validRequest())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(header().doesNotExist("Location"));
    }

    // ---------------------------------------------------------------
    // 5. Missing state → 400, JSON OAuth error
    // ---------------------------------------------------------------
    @Test
    void missingState_returns400JsonError() throws Exception {
        when(authorizationService.authorize(any()))
                .thenThrow(new MissingStateException("state is required"));

        mockMvc.perform(validRequest())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(header().doesNotExist("Location"));
    }

    // ---------------------------------------------------------------
    // 6a. Unsupported provider → 400, JSON OAuth error
    // ---------------------------------------------------------------
    @Test
    void unsupportedProvider_returns400JsonError() throws Exception {
        when(authorizationService.authorize(any()))
                .thenThrow(new UnsupportedProviderException("Unsupported provider: MICROSOFT"));

        mockMvc.perform(validRequest())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(header().doesNotExist("Location"));
    }

    // ---------------------------------------------------------------
    // 6b. Unsupported response_type → 400, JSON OAuth error
    // ---------------------------------------------------------------
    @Test
    void unsupportedResponseType_returns400JsonError() throws Exception {
        when(authorizationService.authorize(any()))
                .thenThrow(new UnsupportedResponseTypeException("response_type must be 'code', got: token"));

        mockMvc.perform(get(ENDPOINT)
                        .param("client_id",             CLIENT_ID)
                        .param("response_type",         "token")
                        .param("redirect_uri",          REDIRECT_URI)
                        .param("state",                 STATE)
                        .param("code_challenge",        CHALLENGE)
                        .param("code_challenge_method", METHOD)
                        .param("provider",              PROVIDER))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_response_type"))
                .andExpect(header().doesNotExist("Location"));
    }

    // ---------------------------------------------------------------
    // 6c. Invalid scope → 400, JSON OAuth error ("invalid_scope")
    // ---------------------------------------------------------------
    @Test
    void invalidScope_returns400JsonError() throws Exception {
        when(authorizationService.authorize(any()))
                .thenThrow(new com.eaglesoft.passly.auth_server.authorization.exception.InvalidScopeException("Invalid scope: admin"));

        mockMvc.perform(validRequest().param("scope", "admin"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_scope"))
                .andExpect(jsonPath("$.error_description").value("Invalid scope: admin"))
                .andExpect(header().doesNotExist("Location"));
    }

    // ---------------------------------------------------------------
    // 7. HTTP query parameters are correctly mapped to AuthorizeCommand
    // ---------------------------------------------------------------
    @Test
    void queryParametersAreMappedToCommandCorrectly() throws Exception {
        when(authorizationService.authorize(any()))
                .thenReturn(new AuthorizationResult(STATE, REDIRECT_URL));

        mockMvc.perform(validRequest().param("scope", "openid profile"));

        ArgumentCaptor<AuthorizeCommand> captor = ArgumentCaptor.forClass(AuthorizeCommand.class);
        verify(authorizationService).authorize(captor.capture());

        AuthorizeCommand command = captor.getValue();
        assertThat(command.clientId()).isEqualTo(CLIENT_ID);
        assertThat(command.responseType()).isEqualTo("code");
        assertThat(command.redirectUri()).isEqualTo(REDIRECT_URI);
        assertThat(command.state()).isEqualTo(STATE);
        assertThat(command.codeChallenge()).isEqualTo(CHALLENGE);
        assertThat(command.codeChallengeMethod()).isEqualTo(METHOD);
        assertThat(command.provider()).isEqualTo(PROVIDER);
        assertThat(command.scope()).isEqualTo("openid profile");
    }
}
