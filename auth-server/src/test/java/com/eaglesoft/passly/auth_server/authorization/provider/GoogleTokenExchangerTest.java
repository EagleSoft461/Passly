package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.exception.TokenExchangeException;
import com.eaglesoft.passly.auth_server.authorization.model.ExternalTokenResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withServerError;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class GoogleTokenExchangerTest {

    private MockRestServiceServer mockServer;
    private GoogleTokenExchanger exchanger;

    @BeforeEach
    void setUp() {
        GoogleOAuthProperties properties = new GoogleOAuthProperties(
                "client-id-123",
                "secret-abc",
                "http://localhost/callback",
                "openid"
        );

        RestClient.Builder builder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(builder).build();

        exchanger = new GoogleTokenExchanger(properties, builder);
    }

    @Test
    void shouldReturnProviderName() {
        assertThat(exchanger.supports()).isEqualTo("GOOGLE");
    }

    @Test
    void shouldExchangeCodeSuccessfully() {
        String jsonResponse = """
                {
                  "access_token": "google-access-token",
                  "expires_in": 3599,
                  "id_token": "google-id-token",
                  "scope": "openid email",
                  "token_type": "Bearer",
                  "refresh_token": "google-refresh-token"
                }
                """;

        mockServer.expect(requestTo("https://oauth2.googleapis.com/token"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("client_id=client-id-123")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("client_secret=secret-abc")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("code=auth-code-xyz")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("grant_type=authorization_code")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("redirect_uri=http%3A%2F%2Flocalhost%2Fcallback")))
                .andRespond(withSuccess(jsonResponse, MediaType.APPLICATION_JSON));

        ExternalTokenResponse response = exchanger.exchangeCode("auth-code-xyz");

        assertThat(response).isNotNull();
        assertThat(response.accessToken()).isEqualTo("google-access-token");
        assertThat(response.expiresIn()).isEqualTo(3599);
        assertThat(response.idToken()).isEqualTo("google-id-token");
        assertThat(response.scope()).isEqualTo("openid email");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.refreshToken()).isEqualTo("google-refresh-token");

        mockServer.verify();
    }

    @Test
    void shouldThrowExceptionWhenExchangeFails() {
        mockServer.expect(requestTo("https://oauth2.googleapis.com/token"))
                .andRespond(withServerError());

        assertThatThrownBy(() -> exchanger.exchangeCode("auth-code-xyz"))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("Failed to exchange Google authorization code");

        mockServer.verify();
    }
}
