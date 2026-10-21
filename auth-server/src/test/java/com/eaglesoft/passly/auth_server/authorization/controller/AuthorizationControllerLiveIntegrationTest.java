package com.eaglesoft.passly.auth_server.authorization.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.startsWith;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationControllerLiveIntegrationTest {

    private static final String CLIENT_ID = "passly-demo-client";
    private static final String REDIRECT_URI = "http://localhost:8080/login/oauth2/code/passly-demo";
    private static final String STATE = "LysEQS-wLAWt5nntfvucd-97SHwUZ8bFH1cbyRw38TM";
    private static final String CODE_CHALLENGE = "9OYhVAsgfjDTNrF0RbrBfv-EIlU0glSeoZKa3BAy9YQ";
    private static final String CODE_CHALLENGE_METHOD = "S256";

    @Autowired
    private MockMvc mockMvc;

    @Test
    void shouldSuccessfullyInitiateAuthorizeFlowAndRedirectToGoogle() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "profile email")
                        .param("state", STATE)
                        .param("code_challenge", CODE_CHALLENGE)
                        .param("code_challenge_method", CODE_CHALLENGE_METHOD)
                        .param("provider", "google"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", startsWith("https://accounts.google.com/o/oauth2/v2/auth")))
                .andExpect(header().string("Location", containsString("state=" + STATE)))
                .andExpect(header().string("Location", containsString("response_type=code")));
    }

    @Test
    void shouldReturn400WhenRedirectUriDoesNotMatch() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", "http://localhost:8080/unauthorized-callback")
                        .param("scope", "profile email")
                        .param("state", STATE)
                        .param("code_challenge", CODE_CHALLENGE)
                        .param("code_challenge_method", CODE_CHALLENGE_METHOD)
                        .param("provider", "google"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"))
                .andExpect(jsonPath("$.error_description").value(containsString("redirect_uri is not registered")));
    }

    @Test
    void shouldReturn400WhenScopeIsUnauthorized() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "admin")
                        .param("state", STATE)
                        .param("code_challenge", CODE_CHALLENGE)
                        .param("code_challenge_method", CODE_CHALLENGE_METHOD)
                        .param("provider", "google"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_scope"))
                .andExpect(jsonPath("$.error_description").value(containsString("Invalid or unauthorized scope requested")));
    }

    @Test
    void shouldReturn400WhenClientIsUnknown() throws Exception {
        mockMvc.perform(get("/oauth2/authorize")
                        .param("response_type", "code")
                        .param("client_id", "unknown-client")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", "profile email")
                        .param("state", STATE)
                        .param("code_challenge", CODE_CHALLENGE)
                        .param("code_challenge_method", CODE_CHALLENGE_METHOD)
                        .param("provider", "google"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }
}
