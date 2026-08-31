package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.MissingStateException;
import com.eaglesoft.passly.auth_server.authorization.exception.UnsupportedResponseTypeException;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationResult;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizeCommand;
import com.eaglesoft.passly.auth_server.authorization.provider.IdentityProvider;
import com.eaglesoft.passly.auth_server.authorization.provider.IdentityProviderResolver;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;

@Service
public class AuthorizationServiceImpl implements AuthorizationService {

    private static final Duration REQUEST_TTL = Duration.ofMinutes(5); // Decision 7

    private final OAuthClientService oAuthClientService;
    private final PkceValidator pkceValidator;
    private final AuthorizationRequestService authorizationRequestService;
    private final IdentityProviderResolver identityProviderResolver;

    public AuthorizationServiceImpl(OAuthClientService oAuthClientService,
                                    PkceValidator pkceValidator,
                                    AuthorizationRequestService authorizationRequestService,
                                    IdentityProviderResolver identityProviderResolver) {
        this.oAuthClientService = oAuthClientService;
        this.pkceValidator = pkceValidator;
        this.authorizationRequestService = authorizationRequestService;
        this.identityProviderResolver = identityProviderResolver;
    }

    @Override
    public AuthorizationResult authorize(AuthorizeCommand command) {
        // Order matters: client/redirect_uri first, since a failure here
        // means we cannot safely redirect an error back to the client at all
        // (see docs/api-contract.md error table).
        oAuthClientService.validateClientAndRedirectUri(command.clientId(), command.redirectUri());

        requireState(command.state());
        requireCodeResponseType(command.responseType());

        // Resolve the provider before PKCE and save so that an unsupported
        // provider is rejected early, at the same logical stage as state/
        // response_type validation. Resolution implicitly validates the
        // provider name (throws UnsupportedProviderException if unknown).
        IdentityProvider provider = identityProviderResolver.resolve(command.provider());

        pkceValidator.validate(command.codeChallenge(), command.codeChallengeMethod());

        AuthorizationRequest request = new AuthorizationRequest(
                command.state(),
                command.clientId(),
                command.redirectUri(),
                command.codeChallenge(),
                command.codeChallengeMethod(),
                command.provider(),
                Instant.now().plus(REQUEST_TTL)
        );
        authorizationRequestService.save(request);

        String redirectUrl = provider.buildAuthorizationUrl(request);

        return new AuthorizationResult(command.state(), redirectUrl);
    }

    private void requireState(String state) {
        if (!StringUtils.hasText(state)) {
            throw new MissingStateException("state is required");
        }
    }

    private void requireCodeResponseType(String responseType) {
        if (!"code".equals(responseType)) {
            throw new UnsupportedResponseTypeException(
                    "response_type must be 'code', got: " + responseType);
        }
    }
}
