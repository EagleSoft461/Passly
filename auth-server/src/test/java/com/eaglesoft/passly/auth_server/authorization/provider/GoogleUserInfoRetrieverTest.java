package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.exception.ExternalIdentityRetrievalException;
import com.eaglesoft.passly.auth_server.authorization.model.ExternalUserInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.*;

class GoogleUserInfoRetrieverTest {

    private MockRestServiceServer mockServer;
    private GoogleUserInfoRetriever retriever;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        mockServer = MockRestServiceServer.bindTo(builder).build();
        retriever = new GoogleUserInfoRetriever(builder);
    }

    @Test
    void shouldReturnProviderName() {
        assertThat(retriever.supports()).isEqualTo("GOOGLE");
    }

    @Test
    void shouldRetrieveUserInfoSuccessfully() {
        String jsonResponse = """
                {
                  "sub": "108573926582368593847",
                  "email": "ali@gmail.com",
                  "email_verified": true,
                  "name": "Ali Yılmaz",
                  "picture": "https://lh3.googleusercontent.com/a/default-user"
                }
                """;

        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v3/userinfo"))
                .andExpect(method(HttpMethod.GET))
                .andExpect(header("Authorization", "Bearer google-access-token-123"))
                .andRespond(withSuccess(jsonResponse, MediaType.APPLICATION_JSON));

        ExternalUserInfo userInfo = retriever.retrieveUserInfo("google-access-token-123");

        assertThat(userInfo).isNotNull();
        assertThat(userInfo.sub()).isEqualTo("108573926582368593847");
        assertThat(userInfo.email()).isEqualTo("ali@gmail.com");
        assertThat(userInfo.emailVerified()).isTrue();
        assertThat(userInfo.name()).isEqualTo("Ali Yılmaz");
        assertThat(userInfo.picture()).isEqualTo("https://lh3.googleusercontent.com/a/default-user");

        mockServer.verify();
    }

    @Test
    void shouldHandleUnverifiedEmail() {
        String jsonResponse = """
                {
                  "sub": "108573926582368593847",
                  "email": "unverified@example.com",
                  "email_verified": false,
                  "name": "Test User"
                }
                """;

        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v3/userinfo"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(jsonResponse, MediaType.APPLICATION_JSON));

        ExternalUserInfo userInfo = retriever.retrieveUserInfo("access-token");

        assertThat(userInfo.emailVerified()).isFalse();
        mockServer.verify();
    }

    @Test
    void shouldThrowExceptionOn401Unauthorized() {
        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v3/userinfo"))
                .andRespond(withUnauthorizedRequest());

        assertThatThrownBy(() -> retriever.retrieveUserInfo("invalid-token"))
                .isInstanceOf(ExternalIdentityRetrievalException.class)
                .hasMessageContaining("Failed to retrieve Google user info");

        mockServer.verify();
    }

    @Test
    void shouldThrowExceptionOn403Forbidden() {
        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v3/userinfo"))
                .andRespond(withStatus(org.springframework.http.HttpStatus.FORBIDDEN));

        assertThatThrownBy(() -> retriever.retrieveUserInfo("insufficient-scope-token"))
                .isInstanceOf(ExternalIdentityRetrievalException.class)
                .hasMessageContaining("Failed to retrieve Google user info");

        mockServer.verify();
    }

    @Test
    void shouldThrowExceptionOn5xxServerError() {
        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v3/userinfo"))
                .andRespond(withServerError());

        assertThatThrownBy(() -> retriever.retrieveUserInfo("valid-token"))
                .isInstanceOf(ExternalIdentityRetrievalException.class)
                .hasMessageContaining("Failed to retrieve Google user info");

        mockServer.verify();
    }

    @Test
    void shouldThrowExceptionOnMalformedResponse() {
        String malformedJson = "{ invalid json }";

        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v3/userinfo"))
                .andRespond(withSuccess(malformedJson, MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> retriever.retrieveUserInfo("valid-token"))
                .isInstanceOf(ExternalIdentityRetrievalException.class)
                .hasMessageContaining("Failed to retrieve Google user info");

        mockServer.verify();
    }

    @Test
    void shouldThrowExceptionWhenSubIsMissing() {
        String jsonResponse = """
                {
                  "email": "ali@gmail.com",
                  "email_verified": true,
                  "name": "Ali"
                }
                """;

        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v3/userinfo"))
                .andRespond(withSuccess(jsonResponse, MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> retriever.retrieveUserInfo("valid-token"))
                .isInstanceOf(ExternalIdentityRetrievalException.class);

        mockServer.verify();
    }

    @Test
    void shouldThrowExceptionWhenEmailIsMissing() {
        String jsonResponse = """
                {
                  "sub": "108573926582368593847",
                  "email_verified": true,
                  "name": "Ali"
                }
                """;

        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v3/userinfo"))
                .andRespond(withSuccess(jsonResponse, MediaType.APPLICATION_JSON));

        assertThatThrownBy(() -> retriever.retrieveUserInfo("valid-token"))
                .isInstanceOf(ExternalIdentityRetrievalException.class);

        mockServer.verify();
    }

    @Test
    void shouldNotLeakAccessTokenInExceptionMessage() {
        mockServer.expect(requestTo("https://www.googleapis.com/oauth2/v3/userinfo"))
                .andRespond(withServerError());

        String sensitiveToken = "super-secret-access-token-12345";

        assertThatThrownBy(() -> retriever.retrieveUserInfo(sensitiveToken))
                .isInstanceOf(ExternalIdentityRetrievalException.class)
                .hasMessageNotContaining(sensitiveToken)
                .hasMessageContaining("Failed to retrieve Google user info");

        mockServer.verify();
    }
}
