package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.exception.UnsupportedProviderException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class IdentityProviderResolverTest {

    @Mock
    private IdentityProvider googleProvider;

    @Mock
    private IdentityProvider gitHubProvider;

    @Test
    void shouldResolveGoogleProvider() {
        lenient().when(googleProvider.supports()).thenReturn("GOOGLE");
        lenient().when(gitHubProvider.supports()).thenReturn("GITHUB");

        IdentityProviderResolver resolver = new IdentityProviderResolver(List.of(googleProvider, gitHubProvider));
        IdentityProvider result = resolver.resolve("GOOGLE");

        assertThat(result).isSameAs(googleProvider);
    }

    @Test
    void shouldResolveGitHubProvider() {
        lenient().when(googleProvider.supports()).thenReturn("GOOGLE");
        lenient().when(gitHubProvider.supports()).thenReturn("GITHUB");

        IdentityProviderResolver resolver = new IdentityProviderResolver(List.of(googleProvider, gitHubProvider));
        IdentityProvider result = resolver.resolve("GITHUB");

        assertThat(result).isSameAs(gitHubProvider);
    }

    @Test
    void shouldResolveProviderCaseInsensitively() {
        lenient().when(googleProvider.supports()).thenReturn("GOOGLE");

        IdentityProviderResolver resolver = new IdentityProviderResolver(List.of(googleProvider));
        IdentityProvider result = resolver.resolve("google");

        assertThat(result).isSameAs(googleProvider);
    }

    @Test
    void shouldThrowWhenProviderNotSupported() {
        lenient().when(googleProvider.supports()).thenReturn("GOOGLE");
        lenient().when(gitHubProvider.supports()).thenReturn("GITHUB");

        IdentityProviderResolver resolver = new IdentityProviderResolver(List.of(googleProvider, gitHubProvider));

        assertThatThrownBy(() -> resolver.resolve("MICROSOFT"))
                .isInstanceOf(UnsupportedProviderException.class)
                .hasMessage("Unsupported provider: MICROSOFT");
    }

}
