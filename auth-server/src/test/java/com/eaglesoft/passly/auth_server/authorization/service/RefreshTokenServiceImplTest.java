package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.TokenExchangeException;
import com.eaglesoft.passly.auth_server.authorization.model.RotatedRefreshToken;
import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import com.eaglesoft.passly.auth_server.domain.RefreshToken;
import com.eaglesoft.passly.auth_server.domain.User;
import com.eaglesoft.passly.auth_server.repository.RefreshTokenRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RefreshTokenServiceImplTest {

    private static final String CLIENT_ID = "test-client";

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    private RefreshTokenServiceImpl refreshTokenService;

    private OAuthClient activeClient;
    private User testUser;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenServiceImpl(
                refreshTokenRepository
        );

        activeClient = new OAuthClient(
                CLIENT_ID,
                "secret-hash",
                "Test Client",
                Collections.singletonList(
                        "https://client.example.com/callback"
                ),
                Collections.singletonList("openid")
        );

        testUser = new User("test@example.com");
    }

    // -------------------------------------------------------------------------
    // 1. CREATE
    // -------------------------------------------------------------------------

    @Test
    void shouldCreateRefreshToken() {

        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        String plaintextToken =
                refreshTokenService.create(testUser, activeClient);

        assertThat(plaintextToken)
                .isNotBlank();

        assertThat(plaintextToken.length())
                .isGreaterThan(40);

        ArgumentCaptor<RefreshToken> captor =
                ArgumentCaptor.forClass(RefreshToken.class);

        verify(refreshTokenRepository)
                .save(captor.capture());

        RefreshToken savedToken = captor.getValue();

        assertThat(savedToken.getUser())
                .isSameAs(testUser);

        assertThat(savedToken.getClient())
                .isSameAs(activeClient);

        assertThat(savedToken.getTokenHash())
                .isNotBlank();

        assertThat(savedToken.getTokenHash())
                .isNotEqualTo(plaintextToken);

        assertThat(savedToken.getTokenFamilyId())
                .isNotNull();

        assertThat(savedToken.getExpiresAt())
                .isAfter(Instant.now());
    }

    // -------------------------------------------------------------------------
    // 2. ROTATION
    // -------------------------------------------------------------------------

    @Test
    void shouldRotateRefreshTokenSuccessfully() {

        String plaintextToken = "existing-refresh-token";

        UUID familyId = UUID.randomUUID();

        RefreshToken existing = new RefreshToken(
                testUser,
                activeClient,
                "hashed-existing-token",
                familyId,
                Instant.now().plusSeconds(3600)
        );

        when(refreshTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.of(existing));

        when(refreshTokenRepository.save(any(RefreshToken.class)))
        .thenAnswer(invocation -> {

            RefreshToken token = invocation.getArgument(0);

            if (token.getId() == null) {
                setEntityId(token);
            }

            return token;
        });

        RotatedRefreshToken rotated =
                refreshTokenService.rotate(
                        plaintextToken,
                        activeClient
                );

        assertThat(rotated)
                .isNotNull();

        assertThat(rotated.plaintextToken())
                .isNotBlank();

        assertThat(rotated.user())
                .isSameAs(testUser);

        assertThat(existing.isRevoked())
                .isTrue();

        assertThat(existing.getReplacedBy())
                .isNotNull();

        verify(refreshTokenRepository, atLeast(2))
                .save(any(RefreshToken.class));
    }

    // -------------------------------------------------------------------------
    // 3. INVALID TOKEN
    // -------------------------------------------------------------------------

    @Test
    void shouldRejectUnknownRefreshToken() {

        when(refreshTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() ->
                refreshTokenService.rotate(
                        "unknown-refresh-token",
                        activeClient
                ))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("Invalid refresh token");
    }

    // -------------------------------------------------------------------------
    // 4. EXPIRED TOKEN
    // -------------------------------------------------------------------------

    @Test
    void shouldRejectExpiredRefreshToken() {

        RefreshToken expiredToken = new RefreshToken(
                testUser,
                activeClient,
                "hashed-expired-token",
                UUID.randomUUID(),
                Instant.now().minusSeconds(60)
        );

        when(refreshTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.of(expiredToken));

        when(refreshTokenRepository.save(any(RefreshToken.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        assertThatThrownBy(() ->
                refreshTokenService.rotate(
                        "expired-refresh-token",
                        activeClient
                ))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("Refresh token expired");

        assertThat(expiredToken.isRevoked())
                .isTrue();

        verify(refreshTokenRepository)
                .save(expiredToken);
    }

    // -------------------------------------------------------------------------
    // 5. REVOKED TOKEN / REUSE DETECTION
    // -------------------------------------------------------------------------

    @Test
    void shouldDetectRefreshTokenReuseAndRevokeFamily() {

        UUID familyId = UUID.randomUUID();

        RefreshToken revokedToken = new RefreshToken(
                testUser,
                activeClient,
                "hashed-reused-token",
                familyId,
                Instant.now().plusSeconds(3600)
        );

        revokedToken.revoke();

        RefreshToken activeFamilyToken = new RefreshToken(
                testUser,
                activeClient,
                "hashed-active-token",
                familyId,
                Instant.now().plusSeconds(3600)
        );

        when(refreshTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.of(revokedToken));

        when(refreshTokenRepository
                .findAllByTokenFamilyIdAndRevokedAtIsNull(familyId))
                .thenReturn(List.of(activeFamilyToken));

        assertThatThrownBy(() ->
                refreshTokenService.rotate(
                        "reused-refresh-token",
                        activeClient
                ))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining("Refresh token reuse detected");

        assertThat(activeFamilyToken.isRevoked())
                .isTrue();

        verify(refreshTokenRepository)
                .saveAll(List.of(activeFamilyToken));
    }

    // -------------------------------------------------------------------------
    // 6. WRONG CLIENT
    // -------------------------------------------------------------------------

    @Test
    void shouldRejectRefreshTokenBelongingToAnotherClient() {

        OAuthClient anotherClient = new OAuthClient(
                "another-client",
                "secret-hash",
                "Another Client",
                Collections.singletonList(
                        "https://another.example.com/callback"
                ),
                Collections.singletonList("openid")
        );

        RefreshToken token = new RefreshToken(
                testUser,
                anotherClient,
                "hashed-token",
                UUID.randomUUID(),
                Instant.now().plusSeconds(3600)
        );

        when(refreshTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.of(token));

        assertThatThrownBy(() ->
                refreshTokenService.rotate(
                        "refresh-token",
                        activeClient
                ))
                .isInstanceOf(TokenExchangeException.class)
                .hasMessageContaining(
                        "Refresh token does not belong to client"
                );

        verify(refreshTokenRepository, never())
                .save(any(RefreshToken.class));
    }

    // -------------------------------------------------------------------------
    // 7. REVOKE
    // -------------------------------------------------------------------------

    @Test
    void shouldRevokeRefreshToken() {

        RefreshToken token = new RefreshToken(
                testUser,
                activeClient,
                "hashed-token",
                UUID.randomUUID(),
                Instant.now().plusSeconds(3600)
        );

        when(refreshTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.of(token));

        refreshTokenService.revoke("refresh-token");

        assertThat(token.isRevoked())
                .isTrue();

        verify(refreshTokenRepository)
                .save(token);
    }

    // -------------------------------------------------------------------------
    // 8. REVOKE UNKNOWN TOKEN
    // -------------------------------------------------------------------------

    @Test
    void shouldIgnoreUnknownTokenDuringRevoke() {

        when(refreshTokenRepository.findByTokenHash(anyString()))
                .thenReturn(Optional.empty());

        refreshTokenService.revoke("unknown-token");

        verify(refreshTokenRepository, never())
                .save(any(RefreshToken.class));
    }

    // -------------------------------------------------------------------------
    // 9. REVOKE FAMILY
    // -------------------------------------------------------------------------

    @Test
    void shouldRevokeAllActiveTokensInFamily() {

        UUID familyId = UUID.randomUUID();

        RefreshToken token1 = new RefreshToken(
                testUser,
                activeClient,
                "hash-1",
                familyId,
                Instant.now().plusSeconds(3600)
        );

        RefreshToken token2 = new RefreshToken(
                testUser,
                activeClient,
                "hash-2",
                familyId,
                Instant.now().plusSeconds(3600)
        );

        when(refreshTokenRepository
                .findAllByTokenFamilyIdAndRevokedAtIsNull(familyId))
                .thenReturn(List.of(token1, token2));

        refreshTokenService.revokeFamily(token1);

        assertThat(token1.isRevoked())
                .isTrue();

        assertThat(token2.isRevoked())
                .isTrue();

        verify(refreshTokenRepository)
                .saveAll(List.of(token1, token2));
    }

    private static void setEntityId(RefreshToken token) {
    try {
        var field = RefreshToken.class.getDeclaredField("id");
        field.setAccessible(true);
        field.set(token, UUID.randomUUID());
    } catch (ReflectiveOperationException e) {
        throw new AssertionError("Failed to assign test entity ID", e);
    }
}
}