package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.InvalidClientException;
import com.eaglesoft.passly.auth_server.authorization.exception.InvalidPkceException;
import com.eaglesoft.passly.auth_server.authorization.exception.InvalidRedirectUriException;
import com.eaglesoft.passly.auth_server.authorization.exception.MissingStateException;
import com.eaglesoft.passly.auth_server.authorization.exception.UnsupportedProviderException;
import com.eaglesoft.passly.auth_server.authorization.exception.UnsupportedResponseTypeException;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationResult;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizeCommand;
import com.eaglesoft.passly.auth_server.authorization.provider.IdentityProvider;
import com.eaglesoft.passly.auth_server.authorization.provider.IdentityProviderResolver;
import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationServiceImplTest {

    @Mock
    private OAuthClientService oAuthClientService;
    @Mock
    private PkceValidator pkceValidator;
    @Mock
    private AuthorizationRequestService authorizationRequestService;
    @Mock
    private IdentityProviderResolver identityProviderResolver;
    @Mock
    private IdentityProvider mockProvider;

    @InjectMocks
    private AuthorizationServiceImpl service;

    @Captor
    private ArgumentCaptor<AuthorizationRequest> requestCaptor;

    private AuthorizeCommand validCommand() {
        return new AuthorizeCommand(
                "passly-demo-client",
                "code",
                "http://localhost:8080/login/oauth2/code/passly-demo",
                "client-state-abc",
                "challenge-xyz",
                "S256",
                "GOOGLE"
        );
    }

    private OAuthClient dummyClient() {
        return new OAuthClient("passly-demo-client", "hash", "Demo",
                List.of("http://localhost:8080/login/oauth2/code/passly-demo"),
                List.of("openid"));
    }

    @Test
    void shouldReturnRedirectUrlForValidRequest() {
        when(oAuthClientService.validateClientAndRedirectUri(any(), any())).thenReturn(dummyClient());
        when(identityProviderResolver.resolve(any())).thenReturn(mockProvider);
        when(mockProvider.buildAuthorizationUrl(any()))
                .thenReturn("https://accounts.google.com/o/oauth2/v2/auth?...");

        AuthorizationResult result = service.authorize(validCommand());

        assertThat(result.state()).isEqualTo("client-state-abc");
        assertThat(result.redirectUrl()).isEqualTo("https://accounts.google.com/o/oauth2/v2/auth?...");
    }

    @Test
    void shouldPersistAuthorizationRequestWithFieldsFromCommand() {
        when(oAuthClientService.validateClientAndRedirectUri(any(), any())).thenReturn(dummyClient());
        when(identityProviderResolver.resolve(any())).thenReturn(mockProvider);
        when(mockProvider.buildAuthorizationUrl(any())).thenReturn("https://example.test");

        service.authorize(validCommand());

        verify(authorizationRequestService).save(requestCaptor.capture());
        AuthorizationRequest saved = requestCaptor.getValue();
        assertThat(saved.state()).isEqualTo("client-state-abc");
        assertThat(saved.clientId()).isEqualTo("passly-demo-client");
        assertThat(saved.codeChallenge()).isEqualTo("challenge-xyz");
        assertThat(saved.provider()).isEqualTo("GOOGLE");
        assertThat(saved.expiresAt()).isAfter(java.time.Instant.now());
    }

    @Test
    void shouldPropagateInvalidClientException() {
        // Unknown-vs-disabled distinction is already covered by
        // OAuthClientServiceImplTest — here we only confirm propagation.
        when(oAuthClientService.validateClientAndRedirectUri(any(), any()))
                .thenThrow(new InvalidClientException("unknown client"));

        assertThatThrownBy(() -> service.authorize(validCommand()))
                .isInstanceOf(InvalidClientException.class);

        verifyNoInteractions(authorizationRequestService, identityProviderResolver);
    }

    @Test
    void shouldPropagateInvalidRedirectUriException() {
        when(oAuthClientService.validateClientAndRedirectUri(any(), any()))
                .thenThrow(new InvalidRedirectUriException("redirect_uri mismatch"));

        assertThatThrownBy(() -> service.authorize(validCommand()))
                .isInstanceOf(InvalidRedirectUriException.class);

        verifyNoInteractions(authorizationRequestService, identityProviderResolver);
    }

    @Test
    void shouldRejectMissingState() {
        when(oAuthClientService.validateClientAndRedirectUri(any(), any())).thenReturn(dummyClient());
        AuthorizeCommand command = new AuthorizeCommand(
                "passly-demo-client",
                "code",
                "http://localhost:8080/login/oauth2/code/passly-demo",
                null, // missing state
                "challenge-xyz", "S256", "GOOGLE"
        );

        assertThatThrownBy(() -> service.authorize(command))
                .isInstanceOf(MissingStateException.class);

        verifyNoInteractions(authorizationRequestService, identityProviderResolver);
    }

    @Test
    void shouldRejectUnsupportedProvider() {
        when(oAuthClientService.validateClientAndRedirectUri(any(), any())).thenReturn(dummyClient());
        when(identityProviderResolver.resolve(any()))
                .thenThrow(new UnsupportedProviderException("Unsupported provider: MICROSOFT"));
        AuthorizeCommand command = new AuthorizeCommand(
                "passly-demo-client",
                "code",
                "http://localhost:8080/login/oauth2/code/passly-demo",
                "client-state-abc",
                "challenge-xyz", "S256", "MICROSOFT" // not supported
        );

        assertThatThrownBy(() -> service.authorize(command))
                .isInstanceOf(UnsupportedProviderException.class);

        verifyNoInteractions(authorizationRequestService);
    }

    @Test
    void shouldRejectUnsupportedResponseType() {
        when(oAuthClientService.validateClientAndRedirectUri(any(), any())).thenReturn(dummyClient());
        AuthorizeCommand command = new AuthorizeCommand(
                "passly-demo-client",
                "token", // not "code"
                "http://localhost:8080/login/oauth2/code/passly-demo",
                "client-state-abc",
                "challenge-xyz", "S256", "GOOGLE"
        );

        assertThatThrownBy(() -> service.authorize(command))
                .isInstanceOf(UnsupportedResponseTypeException.class);

        verifyNoInteractions(authorizationRequestService, identityProviderResolver);
    }

    @Test
    void shouldPropagatePkceValidationFailure() {
        // Missing-challenge vs unsupported-method is already covered by
        // PkceValidatorTest — here we only confirm propagation and that
        // nothing downstream runs.
        when(oAuthClientService.validateClientAndRedirectUri(any(), any())).thenReturn(dummyClient());
        when(identityProviderResolver.resolve(any())).thenReturn(mockProvider);
        doThrow(new InvalidPkceException("code_challenge is required"))
                .when(pkceValidator).validate(any(), any());

        assertThatThrownBy(() -> service.authorize(validCommand()))
                .isInstanceOf(InvalidPkceException.class);

        verifyNoInteractions(authorizationRequestService);
    }

    @Test
    void shouldPropagateRepositorySaveFailure() {
        when(oAuthClientService.validateClientAndRedirectUri(any(), any())).thenReturn(dummyClient());
        when(identityProviderResolver.resolve(any())).thenReturn(mockProvider);
        doThrow(new IllegalStateException("Redis unavailable"))
                .when(authorizationRequestService).save(any());

        assertThatThrownBy(() -> service.authorize(validCommand()))
                .isInstanceOf(IllegalStateException.class);
    }
}
