package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.exception.UnsupportedProviderException;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Selects the correct {@link IdentityProvider} for a given provider name.
 *
 * Spring injects all {@code IdentityProvider} beans as a list, so adding
 * a new provider requires only a new {@code @Component} — no changes here
 * (Open/Closed Principle).
 *
 * Provider validation is a natural consequence of resolution: if no
 * implementation handles the requested provider, an
 * {@link UnsupportedProviderException} is thrown. This removes the need for
 * a separate validation step in {@code AuthorizationServiceImpl}.
 */
@Component
public class IdentityProviderResolver {

    private final List<IdentityProvider> providers;

    public IdentityProviderResolver(List<IdentityProvider> providers) {
        this.providers = providers;
    }

    /**
     * Resolves the {@link IdentityProvider} for the given provider name.
     *
     * @param providerName the provider name from the authorization request
     *                     (e.g. "GOOGLE", "GITHUB")
     * @return the matching {@link IdentityProvider}
     * @throws UnsupportedProviderException if no provider handles the given name
     */
    public IdentityProvider resolve(String providerName) {
        return providers.stream()
                .filter(p -> p.supports().equalsIgnoreCase(providerName))
                .findFirst()
                .orElseThrow(() -> new UnsupportedProviderException(
                        "Unsupported provider: " + providerName));
    }
}
