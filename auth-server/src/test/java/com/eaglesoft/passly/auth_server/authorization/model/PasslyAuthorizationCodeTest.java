package com.eaglesoft.passly.auth_server.authorization.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PasslyAuthorizationCodeTest {

    @Test
    void shouldCreateValidAuthorizationCode() {
        UUID userId = UUID.randomUUID();
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(120);

        PasslyAuthorizationCode code = new PasslyAuthorizationCode(
                "abc123xyz",
                userId,
                "client-1",
                "https://example.com/callback",
                "challenge123",
                "S256",
                "openid profile",
                now,
                expiresAt
        );

        assertThat(code.code()).isEqualTo("abc123xyz");
        assertThat(code.userId()).isEqualTo(userId);
        assertThat(code.clientId()).isEqualTo("client-1");
        assertThat(code.redirectUri()).isEqualTo("https://example.com/callback");
        assertThat(code.codeChallenge()).isEqualTo("challenge123");
        assertThat(code.codeChallengeMethod()).isEqualTo("S256");
        assertThat(code.scope()).isEqualTo("openid profile");
        assertThat(code.createdAt()).isEqualTo(now);
        assertThat(code.expiresAt()).isEqualTo(expiresAt);
    }

    @Test
    void shouldRejectNullCode() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                null,
                UUID.randomUUID(),
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("code cannot be null or blank");
    }

    @Test
    void shouldRejectBlankCode() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                "   ",
                UUID.randomUUID(),
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("code cannot be null or blank");
    }

    @Test
    void shouldRejectNullUserId() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                "code123",
                null,
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("userId cannot be null");
    }

    @Test
    void shouldRejectNullClientId() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                "code123",
                UUID.randomUUID(),
                null,
                "https://example.com/callback",
                "challenge",
                "S256",
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("clientId cannot be null or blank");
    }

    @Test
    void shouldRejectBlankClientId() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                "code123",
                UUID.randomUUID(),
                "  ",
                "https://example.com/callback",
                "challenge",
                "S256",
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("clientId cannot be null or blank");
    }

    @Test
    void shouldRejectNullRedirectUri() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                "code123",
                UUID.randomUUID(),
                "client-1",
                null,
                "challenge",
                "S256",
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("redirectUri cannot be null or blank");
    }

    @Test
    void shouldRejectBlankRedirectUri() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                "code123",
                UUID.randomUUID(),
                "client-1",
                "  ",
                "challenge",
                "S256",
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("redirectUri cannot be null or blank");
    }

    @Test
    void shouldRejectNullCodeChallenge() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                "code123",
                UUID.randomUUID(),
                "client-1",
                "https://example.com/callback",
                null,
                "S256",
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("codeChallenge cannot be null");
    }

    @Test
    void shouldRejectBlankCodeChallenge() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                "code123",
                UUID.randomUUID(),
                "client-1",
                "https://example.com/callback",
                "  ",
                "S256",
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("codeChallenge cannot be null");
    }

    @Test
    void shouldRejectNullCodeChallengeMethod() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                "code123",
                UUID.randomUUID(),
                "client-1",
                "https://example.com/callback",
                "challenge",
                null,
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("codeChallengeMethod cannot be null");
    }

    @Test
    void shouldRejectBlankCodeChallengeMethod() {
        assertThatThrownBy(() -> new PasslyAuthorizationCode(
                "code123",
                UUID.randomUUID(),
                "client-1",
                "https://example.com/callback",
                "challenge",
                "  ",
                Instant.now(),
                Instant.now().plusSeconds(120)
        ))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("codeChallengeMethod cannot be null");
    }

    @Test
    void shouldReturnFalseWhenCodeIsNotExpired() {
        Instant now = Instant.now();
        PasslyAuthorizationCode code = new PasslyAuthorizationCode(
                "code123",
                UUID.randomUUID(),
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                now,
                now.plusSeconds(120)  // Expires 2 minutes from now
        );

        assertThat(code.isExpired()).isFalse();
    }

    @Test
    void shouldReturnTrueWhenCodeIsExpired() {
        Instant now = Instant.now();
        PasslyAuthorizationCode code = new PasslyAuthorizationCode(
                "code123",
                UUID.randomUUID(),
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                now.minusSeconds(200),  // Created 200 seconds ago
                now.minusSeconds(80)    // Expired 80 seconds ago
        );

        assertThat(code.isExpired()).isTrue();
    }
}
