package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.TokenExchangeException;
import com.eaglesoft.passly.auth_server.authorization.model.PasslyAuthorizationCode;
import com.eaglesoft.passly.auth_server.authorization.model.RotatedRefreshToken;
import com.eaglesoft.passly.auth_server.authorization.model.TokenRequest;
import com.eaglesoft.passly.auth_server.authorization.model.TokenResponse;
import com.eaglesoft.passly.auth_server.authorization.repository.PasslyAuthorizationCodeRepository;
import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import com.eaglesoft.passly.auth_server.domain.User;
import com.eaglesoft.passly.auth_server.repository.OAuthClientRepository;
import com.eaglesoft.passly.auth_server.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenServiceImplTest {

    private static final String CLIENT_ID = "test-client";
    private static final String REDIRECT_URI = "https://client.example.com/callback";
    private static final String AUTH_CODE = "secure-random-auth-code";

    // A-Z, a-z, 0-9, -, ., _, ~ (43-128 characters)
    // 43 chars verifier
    private static final String CODE_VERIFIER_43 = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    // 128 chars verifier
    private static final String CODE_VERIFIER_128 = "1234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567_";

    private static final String CODE_CHALLENGE_43 = calculateS256Challenge(CODE_VERIFIER_43);
    private static final String CODE_CHALLENGE_128 = calculateS256Challenge(CODE_VERIFIER_128);

    @Mock
    private PasslyAuthorizationCodeRepository authorizationCodeRepository;
    @Mock
    private OAuthClientRepository oauthClientRepository;
    @Mock
    private UserRepository userRepository;
    @Mock
    private JwtTokenService jwtTokenService;
    @Mock
    private RefreshTokenService refreshTokenService;

    private TokenServiceImpl tokenService;

    private OAuthClient activeClient;
    private User testUser;
    private UUID userId;

    @BeforeEach
    void setUp() {
        tokenService = new TokenServiceImpl(
                authorizationCodeRepository,
                oauthClientRepository,
                userRepository,
                jwtTokenService,
                refreshTokenService
        );

        activeClient = new OAuthClient(CLIENT_ID, "secret-hash", "Test Client",
                Collections.singletonList(REDIRECT_URI), Collections.singletonList("openid"));
        userId = UUID.randomUUID();
        testUser = new User("test@example.com");
    }

    private static String calculateS256Challenge(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(verifier.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // -------------------------------------------------------------------------
    // 1. Success Flow Tests
    // -------------------------------------------------------------------------

    @Test
    void shouldSucceedExchangeWith43CharVerifier() {
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, REDIRECT_URI, CLIENT_ID, CODE_VERIFIER_43, null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, CLIENT_ID, REDIRECT_URI, CODE_CHALLENGE_43, "S256",
                Instant.now(), Instant.now().plusSeconds(120));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        when(jwtTokenService.createAccessToken(testUser, activeClient)).thenReturn("mock-access-token");
        when(refreshTokenService.create(testUser, activeClient)).thenReturn("mock-refresh-token");

        TokenResponse response = tokenService.exchange(request);

        assertThat(response.accessToken()).isEqualTo("mock-access-token");
        assertThat(response.refreshToken()).isEqualTo("mock-refresh-token");
        assertThat(response.tokenType()).isEqualTo("Bearer");
        assertThat(response.expiresIn()).isEqualTo(900);
    }

    @Test
    void shouldSucceedExchangeWith128CharVerifier() {
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, REDIRECT_URI, CLIENT_ID, CODE_VERIFIER_128, null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, CLIENT_ID, REDIRECT_URI, CODE_CHALLENGE_128, "S256",
                Instant.now(), Instant.now().plusSeconds(120));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));
        when(userRepository.findById(userId)).thenReturn(Optional.of(testUser));
        when(jwtTokenService.createAccessToken(testUser, activeClient)).thenReturn("mock-access-token");
        when(refreshTokenService.create(testUser, activeClient)).thenReturn("mock-refresh-token");

        TokenResponse response = tokenService.exchange(request);

        assertThat(response.accessToken()).isEqualTo("mock-access-token");
        assertThat(response.refreshToken()).isEqualTo("mock-refresh-token");
    }

    // -------------------------------------------------------------------------
    // 2. PKCE Validation Boundary / formatting checks (PHASE 1)
    // -------------------------------------------------------------------------

    @Test
    void shouldRejectVerifierTooShort_42Chars() {
        String verifier42 = "123456789012345678901234567890123456789012";
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, REDIRECT_URI, CLIENT_ID, verifier42, null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, CLIENT_ID, REDIRECT_URI, CODE_CHALLENGE_43, "S256",
                Instant.now(), Instant.now().plusSeconds(120));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));

        assertThatThrownBy(() -> tokenService.exchange(request))
                .isInstanceOf(TokenExchangeException.class)
                .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                .hasMessageContaining("Invalid code_verifier length");
    }

    @Test
    void shouldRejectVerifierTooLong_129Chars() {
        String verifier129 = CODE_VERIFIER_128 + "a";
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, REDIRECT_URI, CLIENT_ID, verifier129, null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, CLIENT_ID, REDIRECT_URI, CODE_CHALLENGE_43, "S256",
                Instant.now(), Instant.now().plusSeconds(120));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));

        assertThatThrownBy(() -> tokenService.exchange(request))
                .isInstanceOf(TokenExchangeException.class)
                .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                .hasMessageContaining("Invalid code_verifier length");
    }

    @Test
    void shouldRejectVerifierWithInvalidCharacters() {
        String invalidVerifier = CODE_VERIFIER_43.substring(0, 42) + "+";
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, REDIRECT_URI, CLIENT_ID, invalidVerifier, null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, CLIENT_ID, REDIRECT_URI, CODE_CHALLENGE_43, "S256",
                Instant.now(), Instant.now().plusSeconds(120));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));

        assertThatThrownBy(() -> tokenService.exchange(request))
                .isInstanceOf(TokenExchangeException.class)
                .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                .hasMessageContaining("Invalid characters in code_verifier");
    }

    @Test
    void shouldRejectVerifierWithWhitespace() {
        String invalidVerifier = CODE_VERIFIER_43.substring(0, 42) + " ";
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, REDIRECT_URI, CLIENT_ID, invalidVerifier, null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, CLIENT_ID, REDIRECT_URI, CODE_CHALLENGE_43, "S256",
                Instant.now(), Instant.now().plusSeconds(120));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));

        assertThatThrownBy(() -> tokenService.exchange(request))
                .isInstanceOf(TokenExchangeException.class)
                .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                .hasMessageContaining("Invalid characters in code_verifier");
    }

    @Test
    void shouldRejectVerifierWithUnicode() {
        String invalidVerifier = CODE_VERIFIER_43.substring(0, 42) + "ğ";
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, REDIRECT_URI, CLIENT_ID, invalidVerifier, null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, CLIENT_ID, REDIRECT_URI, CODE_CHALLENGE_43, "S256",
                Instant.now(), Instant.now().plusSeconds(120));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));

        assertThatThrownBy(() -> tokenService.exchange(request))
                .isInstanceOf(TokenExchangeException.class)
                .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                .hasMessageContaining("Invalid characters in code_verifier");
    }

    // -------------------------------------------------------------------------
    // 3. Authorization Code Lifecycle & Expiration (PHASE 6)
    // -------------------------------------------------------------------------

    @Test
    void shouldRejectExpiredAuthorizationCode() {
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, REDIRECT_URI, CLIENT_ID, CODE_VERIFIER_43, null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, CLIENT_ID, REDIRECT_URI, CODE_CHALLENGE_43, "S256",
                Instant.now().minusSeconds(300), Instant.now().minusSeconds(180));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));

        assertThatThrownBy(() -> tokenService.exchange(request))
                .isInstanceOf(TokenExchangeException.class)
                .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                .hasMessageContaining("Invalid or expired authorization code");
    }

    // -------------------------------------------------------------------------
    // 4. Mismatch / Attack Scenarios (PHASE 4 & PHASE 11)
    // -------------------------------------------------------------------------

    @Test
    void shouldRejectMismatchedRedirectUri() {
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, "https://different.example.com", CLIENT_ID, CODE_VERIFIER_43, null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, CLIENT_ID, REDIRECT_URI, CODE_CHALLENGE_43, "S256",
                Instant.now(), Instant.now().plusSeconds(120));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));

        assertThatThrownBy(() -> tokenService.exchange(request))
                .isInstanceOf(TokenExchangeException.class)
                .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                .hasMessageContaining("redirect_uri does not match");
    }

    @Test
    void shouldRejectMismatchedClient() {
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, REDIRECT_URI, CLIENT_ID, CODE_VERIFIER_43, null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, "another-client-id", REDIRECT_URI, CODE_CHALLENGE_43, "S256",
                Instant.now(), Instant.now().plusSeconds(120));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));

        assertThatThrownBy(() -> tokenService.exchange(request))
                .isInstanceOf(TokenExchangeException.class)
                .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                .hasMessageContaining("does not belong to client");
    }

    @Test
    void shouldRejectWrongPkceVerifier() {
        TokenRequest request = new TokenRequest(
                "authorization_code", AUTH_CODE, REDIRECT_URI, CLIENT_ID, "wrong-code-verifier-character-set-len-43-ok-x", null);

        PasslyAuthorizationCode passlyCode = new PasslyAuthorizationCode(
                AUTH_CODE, userId, CLIENT_ID, REDIRECT_URI, CODE_CHALLENGE_43, "S256",
                Instant.now(), Instant.now().plusSeconds(120));

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(authorizationCodeRepository.consume(AUTH_CODE)).thenReturn(Optional.of(passlyCode));

        assertThatThrownBy(() -> tokenService.exchange(request))
                .isInstanceOf(TokenExchangeException.class)
                .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                .hasMessageContaining("Invalid code_verifier");
    }

    // -------------------------------------------------------------------------
    // 5. Refresh Token Exchanges (PHASE 8)
    // -------------------------------------------------------------------------

    @Test
    void shouldSucceedRefreshTokenExchange() {
        TokenRequest request = new TokenRequest(
                "refresh_token", null, null, CLIENT_ID, null, "valid-refresh-token");

        RotatedRefreshToken rotated = new RotatedRefreshToken("new-plain-token", testUser);

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(refreshTokenService.rotate("valid-refresh-token", activeClient)).thenReturn(rotated);
        when(jwtTokenService.createAccessToken(testUser, activeClient)).thenReturn("rotated-access-token");

        TokenResponse response = tokenService.exchange(request);

        assertThat(response.accessToken()).isEqualTo("rotated-access-token");
        assertThat(response.refreshToken()).isEqualTo("new-plain-token");
    }

    @Test
    void shouldPropagateRefreshTokenRotationErrorsAsInvalidGrant() {
        TokenRequest request = new TokenRequest(
                "refresh_token", null, null, CLIENT_ID, null, "invalid-refresh-token");

        when(oauthClientRepository.findById(CLIENT_ID)).thenReturn(Optional.of(activeClient));
        when(refreshTokenService.rotate("invalid-refresh-token", activeClient))
                .thenThrow(new TokenExchangeException("invalid_grant", "Invalid refresh token"));

        assertThatThrownBy(() -> tokenService.exchange(request))
                .isInstanceOf(TokenExchangeException.class)
                .hasFieldOrPropertyWithValue("errorCode", "invalid_grant")
                .hasMessageContaining("Invalid refresh token");
    }
}
