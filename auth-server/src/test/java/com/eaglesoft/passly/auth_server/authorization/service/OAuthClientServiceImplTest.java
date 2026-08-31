package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.InvalidClientException;
import com.eaglesoft.passly.auth_server.authorization.exception.InvalidRedirectUriException;
import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import com.eaglesoft.passly.auth_server.repository.OAuthClientRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Field;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OAuthClientServiceImplTest {

    @Mock
    private OAuthClientRepository repository;

    @InjectMocks
    private OAuthClientServiceImpl service;

    private OAuthClient enabledClient(String redirectUri) {
        return new OAuthClient(
                "passly-demo-client",
                "hashed-secret",
                "Passly Demo Client",
                List.of(redirectUri),
                List.of("openid", "profile", "email")
        );
    }

    private OAuthClient disabledClient() throws Exception {
        OAuthClient client = enabledClient("http://localhost:8080/callback");
        Field enabledField = OAuthClient.class.getDeclaredField("enabled");
        enabledField.setAccessible(true);
        enabledField.set(client, false);
        return client;
    }

    @Test
    void shouldValidateWhenClientAndRedirectUriAreCorrect() {
        String redirectUri = "http://localhost:8080/callback";
        when(repository.findById("passly-demo-client"))
                .thenReturn(Optional.of(enabledClient(redirectUri)));

        OAuthClient result = service.validateClientAndRedirectUri("passly-demo-client", redirectUri);

        assertThat(result.getClientId()).isEqualTo("passly-demo-client");
    }

    @Test
    void shouldThrowInvalidClientWhenClientDoesNotExist() {
        when(repository.findById("unknown-client")).thenReturn(Optional.empty());

        assertThatThrownBy(() ->
                service.validateClientAndRedirectUri("unknown-client", "http://localhost:8080/callback"))
                .isInstanceOf(InvalidClientException.class);
    }

    @Test
    void shouldThrowInvalidClientWhenClientIsDisabled() throws Exception {
        when(repository.findById("passly-demo-client")).thenReturn(Optional.of(disabledClient()));

        assertThatThrownBy(() ->
                service.validateClientAndRedirectUri("passly-demo-client", "http://localhost:8080/callback"))
                .isInstanceOf(InvalidClientException.class);
    }

    @Test
    void shouldThrowInvalidRedirectUriWhenNotRegistered() {
        when(repository.findById("passly-demo-client"))
                .thenReturn(Optional.of(enabledClient("http://localhost:8080/callback")));

        assertThatThrownBy(() ->
                service.validateClientAndRedirectUri("passly-demo-client", "http://evil.example/callback"))
                .isInstanceOf(InvalidRedirectUriException.class);
    }

    @Test
    void shouldRejectRedirectUriThatIsOnlyAPrefixMatch() {
        when(repository.findById("passly-demo-client"))
                .thenReturn(Optional.of(enabledClient("http://localhost:8080/callback")));

        // "exact match only" kararını doğrudan sınayan test — sondaki
        // ekstra path segmenti bile reddedilmeli
        assertThatThrownBy(() ->
                service.validateClientAndRedirectUri(
                        "passly-demo-client", "http://localhost:8080/callback/extra"))
                .isInstanceOf(InvalidRedirectUriException.class);
    }
}
