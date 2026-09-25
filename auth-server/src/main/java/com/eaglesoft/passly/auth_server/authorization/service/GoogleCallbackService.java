package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.InvalidStateException;
import com.eaglesoft.passly.auth_server.authorization.exception.UnsupportedProviderException;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationCodeResponse;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import com.eaglesoft.passly.auth_server.authorization.model.ExternalTokenResponse;
import com.eaglesoft.passly.auth_server.authorization.model.ExternalUserInfo;
import com.eaglesoft.passly.auth_server.authorization.provider.ExternalIdentityRetriever;
import com.eaglesoft.passly.auth_server.authorization.provider.IdentityProviderTokenExchanger;
import com.eaglesoft.passly.auth_server.domain.LinkedAccount;
import com.eaglesoft.passly.auth_server.domain.User;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Locale;
import java.util.Optional;

@Service
public class GoogleCallbackService {

    private final AuthorizationRequestService authorizationRequestService;
    private final List<IdentityProviderTokenExchanger> tokenExchangers;
    private final List<ExternalIdentityRetriever> identityRetrievers;
    private final AccountLinkingService accountLinkingService;
    private final AuthorizationCodeService authorizationCodeService;

    public GoogleCallbackService(
            AuthorizationRequestService authorizationRequestService,
            List<IdentityProviderTokenExchanger> tokenExchangers,
            List<ExternalIdentityRetriever> identityRetrievers,
            AccountLinkingService accountLinkingService,
            AuthorizationCodeService authorizationCodeService) {
        this.authorizationRequestService = authorizationRequestService;
        this.tokenExchangers = tokenExchangers;
        this.identityRetrievers = identityRetrievers;
        this.accountLinkingService = accountLinkingService;
        this.authorizationCodeService = authorizationCodeService;
    }

    public AuthorizationCodeResponse handleCallback(String code, String state) {
        if (state == null || state.isBlank()) {
            throw new InvalidStateException("Missing state parameter");
        }
        if (code == null || code.isBlank()) {
            throw new InvalidStateException("Missing code parameter");
        }

        Optional<AuthorizationRequest> optionalRequest = authorizationRequestService.consume(state);

        if (optionalRequest.isEmpty()) {
            throw new InvalidStateException("Invalid, expired, or already consumed state");
        }

        // Preserve AuthorizationRequest reference for code issuance
        AuthorizationRequest authRequest = optionalRequest.get();

        // Step 1: Exchange authorization code for access token
        IdentityProviderTokenExchanger exchanger = tokenExchangers.stream()
                .filter(e -> e.supports().equalsIgnoreCase(authRequest.provider()))
                .findFirst()
                .orElseThrow(() -> new UnsupportedProviderException(
                        "No token exchanger found for provider: " + authRequest.provider()));

        ExternalTokenResponse tokenResponse = exchanger.exchangeCode(code);

        // Step 2: Retrieve external user info
        ExternalIdentityRetriever retriever = identityRetrievers.stream()
                .filter(r -> r.supports().equalsIgnoreCase(authRequest.provider()))
                .findFirst()
                .orElseThrow(() -> new UnsupportedProviderException(
                        "No identity retriever found for provider: " + authRequest.provider()));

        ExternalUserInfo externalUserInfo = retriever.retrieveUserInfo(tokenResponse.accessToken());

        // Step 3: Link or create user account
        LinkedAccount.Provider provider = LinkedAccount.Provider.valueOf(authRequest.provider().toUpperCase(Locale.ROOT));
        User user = accountLinkingService.linkOrCreateUser(provider, externalUserInfo);

        // Step 4: Issue Passly authorization code
        String authorizationCode = authorizationCodeService.issueCode(user, authRequest);

        return new AuthorizationCodeResponse(
                authorizationCode,
                authRequest.redirectUri(),
                authRequest.state()
        );
    }
}
