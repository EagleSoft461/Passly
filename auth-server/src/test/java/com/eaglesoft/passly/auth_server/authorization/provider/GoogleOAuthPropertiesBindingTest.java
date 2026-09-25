package com.eaglesoft.passly.auth_server.authorization.provider;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that {@link GoogleOAuthProperties} is correctly bound from Spring
 * configuration via {@code @ConfigurationPropertiesScan}.
 *
 * <p>Uses a minimal {@link TestConfig} inner class so the test spins up only the
 * properties-binding infrastructure — no DB, no Redis, no security filter chain.
 */
@SpringBootTest(
        classes = GoogleOAuthPropertiesBindingTest.TestConfig.class,
        properties = {
                "passly.oauth.google.client-id=test-google-client-id",
                "passly.oauth.google.client-secret=test-google-secret",
                "passly.oauth.google.redirect-uri=http://localhost:9000/login/oauth2/code/google",
                "passly.oauth.google.scopes=openid email profile"
        }
)
class GoogleOAuthPropertiesBindingTest {

    @Configuration
    @EnableConfigurationProperties(GoogleOAuthProperties.class)
    static class TestConfig {}

    @Autowired
    private GoogleOAuthProperties properties;

    @Test
    void clientIdIsReadFromConfig() {
        assertThat(properties.clientId())
                .as("clientId must NOT be the fallback 'default-client-id' — "
                        + "GOOGLE_CLIENT_ID env var is missing or application.yml "
                        + "placeholder is not resolved")
                .isEqualTo("test-google-client-id");
    }

    @Test
    void redirectUriIsReadFromConfig() {
        assertThat(properties.redirectUri())
                .isEqualTo("http://localhost:9000/login/oauth2/code/google");
    }

    @Test
    void scopesAreReadFromConfig() {
        assertThat(properties.scopes())
                .isEqualTo("openid email profile");
    }

    @Test
    void scopesDefaultAppliedWhenNull() {
        // Exercises the compact-constructor guard path directly
        GoogleOAuthProperties withNullScopes = new GoogleOAuthProperties(
                "cid", "csecret", "http://localhost/cb", null
        );
        assertThat(withNullScopes.scopes())
                .isEqualTo("openid email profile");
    }
}
