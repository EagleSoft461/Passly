package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.InvalidStateException;
import com.eaglesoft.passly.auth_server.authorization.exception.UnsupportedProviderException;
import com.eaglesoft.passly.auth_server.authorization.exception.UnverifiedEmailException;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationCodeResponse;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import com.eaglesoft.passly.auth_server.authorization.model.ExternalTokenResponse;
import com.eaglesoft.passly.auth_server.authorization.model.ExternalUserInfo;
import com.eaglesoft.passly.auth_server.authorization.provider.ExternalIdentityRetriever;
import com.eaglesoft.passly.auth_server.authorization.provider.IdentityProviderTokenExchanger;
import com.eaglesoft.passly.auth_server.domain.LinkedAccount;
import com.eaglesoft.passly.auth_server.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class GoogleCallbackServiceTest {

    @Mock
    private AuthorizationRequestService authorizationRequestService;

    @Mock
    private IdentityProviderTokenExchanger tokenExchanger;

    @Mock
    private ExternalIdentityRetriever identityRetriever;

    @Mock
    private AccountLinkingService accountLinkingService;

    @Mock
    private AuthorizationCodeService authorizationCodeService;

    private GoogleCallbackService googleCallbackService;

    @BeforeEach
    void setUp() {
        googleCallbackService = new GoogleCallbackService(
                authorizationRequestService,
                List.of(tokenExchanger),
                List.of(identityRetriever),
                accountLinkingService,
                authorizationCodeService);
    }

    @Test
    void shouldCompleteFullAccountLinkingFlowAndIssueCode() {
        String state = "valid-state-123";
        String code = "valid-code-456";
        AuthorizationRequest request = new AuthorizationRequest(
                state, "client1", "http://redirect", "challenge", "S256", "GOOGLE", Instant.now().plusSeconds(300));

        ExternalTokenResponse tokenResponse = new ExternalTokenResponse(
                "google-access-token", 3600, "id-token", "scope", "Bearer", "refresh");

        ExternalUserInfo userInfo = new ExternalUserInfo(
                "google-sub-123", "ali@gmail.com", true, "Ali Yılmaz", null);

        User linkedUser = new User("ali@gmail.com");
        String issuedCode = "passly-auth-code-xyz";

        when(authorizationRequestService.consume(state)).thenReturn(Optional.of(request));
        when(tokenExchanger.supports()).thenReturn("GOOGLE");
        when(tokenExchanger.exchangeCode(code)).thenReturn(tokenResponse);
        when(identityRetriever.supports()).thenReturn("GOOGLE");
        when(identityRetriever.retrieveUserInfo("google-access-token")).thenReturn(userInfo);
        when(accountLinkingService.linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo))
                .thenReturn(linkedUser);
        when(authorizationCodeService.issueCode(linkedUser, request)).thenReturn(issuedCode);

        AuthorizationCodeResponse result = googleCallbackService.handleCallback(code, state);

        assertThat(result).isNotNull();
        assertThat(result.authorizationCode()).isEqualTo("passly-auth-code-xyz");
        assertThat(result.redirectUri()).isEqualTo("http://redirect");
        assertThat(result.originalState()).isEqualTo("valid-state-123");

        verify(authorizationRequestService).consume(state);
        verify(tokenExchanger).exchangeCode(code);
        verify(identityRetriever).retrieveUserInfo("google-access-token");
        verify(accountLinkingService).linkOrCreateUser(LinkedAccount.Provider.GOOGLE, userInfo);
        verify(authorizationCodeService).issueCode(linkedUser, request);
    }

    @Test
    void shouldRejectWhenStateIsNull() {
        assertThatThrownBy(() -> googleCallbackService.handleCallback("code", null))
                .isInstanceOf(InvalidStateException.class)
                .hasMessage("Missing state parameter");

        verifyNoInteractions(authorizationRequestService, tokenExchanger, identityRetriever, accountLinkingService, authorizationCodeService);
    }

    @Test
    void shouldRejectWhenStateIsBlank() {
        assertThatThrownBy(() -> googleCallbackService.handleCallback("code", "   "))
                .isInstanceOf(InvalidStateException.class)
                .hasMessage("Missing state parameter");

        verifyNoInteractions(authorizationRequestService, tokenExchanger, identityRetriever, accountLinkingService, authorizationCodeService);
    }

    @Test
    void shouldRejectWhenCodeIsNull() {
        assertThatThrownBy(() -> googleCallbackService.handleCallback(null, "state"))
                .isInstanceOf(InvalidStateException.class)
                .hasMessage("Missing code parameter");

        verifyNoInteractions(authorizationRequestService, tokenExchanger, identityRetriever, accountLinkingService, authorizationCodeService);
    }

    @Test
    void shouldRejectWhenCodeIsBlank() {
        assertThatThrownBy(() -> googleCallbackService.handleCallback("  ", "state"))
                .isInstanceOf(InvalidStateException.class)
                .hasMessage("Missing code parameter");

        verifyNoInteractions(authorizationRequestService, tokenExchanger, identityRetriever, accountLinkingService, authorizationCodeService);
    }

    @Test
    void shouldRejectWhenStateIsUnknownOrAlreadyConsumed() {
        String state = "unknown-state";
        when(authorizationRequestService.consume(state)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> googleCallbackService.handleCallback("code", state))
                .isInstanceOf(InvalidStateException.class)
                .hasMessage("Invalid, expired, or already consumed state");

        verify(authorizationRequestService).consume(state);
        verifyNoInteractions(tokenExchanger, identityRetriever, accountLinkingService, authorizationCodeService);
    }

    @Test
    void shouldThrowExceptionWhenProviderNotSupported() {
        String state = "valid-state-123";
        String code = "valid-code-456";
        AuthorizationRequest request = new AuthorizationRequest(
                state, "client1", "http://redirect", "challenge", "S256", "GITHUB", Instant.now().plusSeconds(300));

        when(authorizationRequestService.consume(state)).thenReturn(Optional.of(request));
        when(tokenExchanger.supports()).thenReturn("GOOGLE");

        assertThatThrownBy(() -> googleCallbackService.handleCallback(code, state))
                .isInstanceOf(UnsupportedProviderException.class)
                .hasMessage("No token exchanger found for provider: GITHUB");
    }

    @Test
    void shouldPropagateUnverifiedEmailException() {
        String state = "valid-state";
        String code = "valid-code";
        AuthorizationRequest request = new AuthorizationRequest(
                state, "client1", "http://redirect", "challenge", "S256", "GOOGLE", Instant.now().plusSeconds(300));

        ExternalTokenResponse tokenResponse = new ExternalTokenResponse(
                "access", 3600, "id", "scope", "Bearer", null);

        ExternalUserInfo unverifiedUserInfo = new ExternalUserInfo(
                "sub-123", "unverified@example.com", false, "User", null);

        when(authorizationRequestService.consume(state)).thenReturn(Optional.of(request));
        when(tokenExchanger.supports()).thenReturn("GOOGLE");
        when(tokenExchanger.exchangeCode(code)).thenReturn(tokenResponse);
        when(identityRetriever.supports()).thenReturn("GOOGLE");
        when(identityRetriever.retrieveUserInfo("access")).thenReturn(unverifiedUserInfo);
        when(accountLinkingService.linkOrCreateUser(any(), any()))
                .thenThrow(new UnverifiedEmailException("Email verification required"));

        assertThatThrownBy(() -> googleCallbackService.handleCallback(code, state))
                .isInstanceOf(UnverifiedEmailException.class)
                .hasMessage("Email verification required");

        verify(accountLinkingService).linkOrCreateUser(LinkedAccount.Provider.GOOGLE, unverifiedUserInfo);
    }

    @Test
    void shouldThrowExceptionWhenIdentityRetrieverNotFound() {
        String state = "valid-state";
        String code = "valid-code";
        AuthorizationRequest request = new AuthorizationRequest(
                state, "client1", "http://redirect", "challenge", "S256", "GOOGLE", Instant.now().plusSeconds(300));

        ExternalTokenResponse tokenResponse = new ExternalTokenResponse(
                "access", 3600, "id", "scope", "Bearer", null);

        when(authorizationRequestService.consume(state)).thenReturn(Optional.of(request));
        when(tokenExchanger.supports()).thenReturn("GOOGLE");
        when(tokenExchanger.exchangeCode(code)).thenReturn(tokenResponse);
        when(identityRetriever.supports()).thenReturn("GITHUB");  // Mismatch

        assertThatThrownBy(() -> googleCallbackService.handleCallback(code, state))
                .isInstanceOf(UnsupportedProviderException.class)
                .hasMessage("No identity retriever found for provider: GOOGLE");

        verifyNoInteractions(accountLinkingService, authorizationCodeService);
    }
}
