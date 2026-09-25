package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import org.junit.jupiter.api.Test;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class GoogleIdentityProviderTest {

    @Test
    void shouldBuildCorrectGoogleAuthorizationUrl() {
        GoogleOAuthProperties properties = new GoogleOAuthProperties(
                "test-client-id",
                "test-secret",
                "http://localhost:9000/callback/google",
                "openid email profile"
        );
        GoogleIdentityProvider provider = new GoogleIdentityProvider(properties);

        AuthorizationRequest request = new AuthorizationRequest(
                "test-state-123!@#", // testing encoding
                "passly-client-id",
                "http://localhost:8080/app",
                "challenge-abc",
                "S256",
                "GOOGLE",
                Instant.now().plusSeconds(300)
        );

        String url = provider.buildAuthorizationUrl(request);

        // Parse the URL to verify its parts
        UriComponents components = UriComponentsBuilder.fromUriString(url).build();

        assertThat(components.getScheme()).isEqualTo("https");
        assertThat(components.getHost()).isEqualTo("accounts.google.com");
        assertThat(components.getPath()).isEqualTo("/o/oauth2/v2/auth");

        var queryParams = components.getQueryParams();

        assertThat(queryParams.getFirst("response_type")).isEqualTo("code");
        assertThat(queryParams.getFirst("client_id")).isEqualTo("test-client-id");
        assertThat(queryParams.getFirst("redirect_uri")).isEqualTo("http://localhost:9000/callback/google");
        assertThat(queryParams.getFirst("scope")).isEqualTo("openid%20email%20profile");

        // Ensure state is sourced from the request
        assertThat(queryParams.getFirst("state")).isEqualTo("test-state-123!@%23");
    }
}
