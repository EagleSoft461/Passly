package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.CodeIssuanceException;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import com.eaglesoft.passly.auth_server.authorization.model.PasslyAuthorizationCode;
import com.eaglesoft.passly.auth_server.authorization.repository.PasslyAuthorizationCodeRepository;
import com.eaglesoft.passly.auth_server.domain.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Base64;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationCodeServiceTest {

    @Mock
    private PasslyAuthorizationCodeRepository codeRepository;

    @Captor
    private ArgumentCaptor<PasslyAuthorizationCode> codeCaptor;

    private AuthorizationCodeService service;

    @BeforeEach
    void setUp() {
        service = new AuthorizationCodeService(codeRepository);
    }

    @Test
    void shouldIssueValidAuthorizationCode() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);

        AuthorizationRequest request = new AuthorizationRequest(
                "state-123",
                "client-1",
                "https://example.com/callback",
                "challenge-xyz",
                "S256",
                "GOOGLE",
                Instant.now().plusSeconds(300)
        );

        String code = service.issueCode(user, request);

        // Verify code is Base64URL without padding
        assertThat(code).isNotBlank();
        assertThat(code).doesNotContain("=");  // No padding
        assertThat(code).matches("^[A-Za-z0-9_-]+$");  // Base64URL alphabet

        // Verify code is ~43 characters (32 bytes -> 43 chars in Base64)
        assertThat(code.length()).isGreaterThanOrEqualTo(43);

        // Verify saved to repository
        verify(codeRepository).save(codeCaptor.capture());

        PasslyAuthorizationCode savedCode = codeCaptor.getValue();
        assertThat(savedCode.code()).isEqualTo(code);
        assertThat(savedCode.userId()).isEqualTo(userId);
        assertThat(savedCode.clientId()).isEqualTo("client-1");
        assertThat(savedCode.redirectUri()).isEqualTo("https://example.com/callback");
        assertThat(savedCode.codeChallenge()).isEqualTo("challenge-xyz");
        assertThat(savedCode.codeChallengeMethod()).isEqualTo("S256");
        assertThat(savedCode.createdAt()).isNotNull();
        assertThat(savedCode.expiresAt()).isNotNull();
        assertThat(savedCode.expiresAt()).isAfter(savedCode.createdAt());
    }

    @Test
    void shouldGenerateUniqueCodes() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);

        AuthorizationRequest request = new AuthorizationRequest(
                "state-123",
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                "GOOGLE",
                Instant.now().plusSeconds(300)
        );

        Set<String> generatedCodes = new HashSet<>();
        int iterations = 100;

        for (int i = 0; i < iterations; i++) {
            String code = service.issueCode(user, request);
            generatedCodes.add(code);
        }

        // All codes should be unique
        assertThat(generatedCodes).hasSize(iterations);
    }

    @Test
    void shouldSetCorrectTtl() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);

        AuthorizationRequest request = new AuthorizationRequest(
                "state-123",
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                "GOOGLE",
                Instant.now().plusSeconds(300)
        );

        service.issueCode(user, request);

        verify(codeRepository).save(codeCaptor.capture());

        PasslyAuthorizationCode code = codeCaptor.getValue();
        long ttlSeconds = code.expiresAt().getEpochSecond() - code.createdAt().getEpochSecond();

        // TTL should be 120 seconds (2 minutes)
        assertThat(ttlSeconds).isEqualTo(120);
    }

    @Test
    void shouldPreserveAllAuthorizationRequestFields() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);

        AuthorizationRequest request = new AuthorizationRequest(
                "state-abc",
                "my-client",
                "https://custom.com/redirect",
                "custom-challenge",
                "S256",
                "GOOGLE",
                Instant.now().plusSeconds(300)
        );

        service.issueCode(user, request);

        verify(codeRepository).save(codeCaptor.capture());

        PasslyAuthorizationCode code = codeCaptor.getValue();
        assertThat(code.clientId()).isEqualTo("my-client");
        assertThat(code.redirectUri()).isEqualTo("https://custom.com/redirect");
        assertThat(code.codeChallenge()).isEqualTo("custom-challenge");
        assertThat(code.codeChallengeMethod()).isEqualTo("S256");
    }

    @Test
    void shouldThrowExceptionWhenRepositorySaveFails() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);

        AuthorizationRequest request = new AuthorizationRequest(
                "state-123",
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                "GOOGLE",
                Instant.now().plusSeconds(300)
        );

        doThrow(new RuntimeException("Redis connection failed"))
                .when(codeRepository).save(any());

        assertThatThrownBy(() -> service.issueCode(user, request))
                .isInstanceOf(CodeIssuanceException.class)
                .hasMessage("Failed to issue authorization code")
                .hasNoCause();  // Security: original exception not wrapped
    }

    @Test
    void shouldNotExposeInternalExceptionDetails() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);

        AuthorizationRequest request = new AuthorizationRequest(
                "state-123",
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                "GOOGLE",
                Instant.now().plusSeconds(300)
        );

        doThrow(new RuntimeException("Redis failed"))
                .when(codeRepository).save(any());

        assertThatThrownBy(() -> service.issueCode(user, request))
                .isInstanceOf(CodeIssuanceException.class)
                .hasMessage("Failed to issue authorization code")
                .hasNoCause()
                .satisfies(ex -> {
                    assertThat(ex.getMessage())
                            .doesNotContainIgnoringCase("redis");

                    assertThat(ex.getMessage())
                            .doesNotContainIgnoringCase("connection");
                });
    }

    @Test
    void shouldGenerateCryptographicallySecureCode() {
        UUID userId = UUID.randomUUID();
        User user = mock(User.class);
        when(user.getId()).thenReturn(userId);

        AuthorizationRequest request = new AuthorizationRequest(
                "state-123",
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                "GOOGLE",
                Instant.now().plusSeconds(300)
        );

        String code = service.issueCode(user, request);

        // Decode Base64URL to verify entropy
        byte[] decoded = Base64.getUrlDecoder().decode(code);

        // Should be exactly 32 bytes
        assertThat(decoded).hasSize(32);

        // Should have good randomness (not all zeros, not all same byte)
        Set<Byte> uniqueBytes = new HashSet<>();
        for (byte b : decoded) {
            uniqueBytes.add(b);
        }
        assertThat(uniqueBytes.size()).isGreaterThan(10);  // At least 10 different byte values
    }

    @Test
    void shouldHandleMultipleUsersAndClients() {
        UUID userId1 = UUID.randomUUID();
        User user1 = mock(User.class);
        when(user1.getId()).thenReturn(userId1);

        UUID userId2 = UUID.randomUUID();
        User user2 = mock(User.class);
        when(user2.getId()).thenReturn(userId2);

        AuthorizationRequest request1 = new AuthorizationRequest(
                "state-1", "client-1", "https://client1.com/callback",
                "challenge1", "S256", "GOOGLE", Instant.now().plusSeconds(300)
        );

        AuthorizationRequest request2 = new AuthorizationRequest(
                "state-2", "client-2", "https://client2.com/callback",
                "challenge2", "S256", "GOOGLE", Instant.now().plusSeconds(300)
        );

        String code1 = service.issueCode(user1, request1);
        String code2 = service.issueCode(user2, request2);

        // Codes should be different
        assertThat(code1).isNotEqualTo(code2);

        // Verify both saved
        verify(codeRepository, times(2)).save(any());
    }
}
