package com.eaglesoft.passly.auth_server.authorization.repository;

import com.eaglesoft.passly.auth_server.authorization.model.PasslyAuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisPasslyAuthorizationCodeRepositoryTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Captor
    private ArgumentCaptor<String> keyCaptor;

    @Captor
    private ArgumentCaptor<Duration> ttlCaptor;

    private RedisPasslyAuthorizationCodeRepository repository;

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        repository = new RedisPasslyAuthorizationCodeRepository(redisTemplate, new ObjectMapper());
    }

    @Test
    void shouldReturnEmptyWhenCodeDoesNotExist() {
        when(valueOperations.getAndDelete("passly:oauth:code:nonexistent")).thenReturn(null);

        Optional<PasslyAuthorizationCode> result = repository.consume("nonexistent");

        assertThat(result).isEmpty();
        verify(valueOperations).getAndDelete("passly:oauth:code:nonexistent");
    }

    @Test
    void shouldReturnEmptyWhenCodeAlreadyConsumed() {
        // Simulates second call after getAndDelete already removed it
        when(valueOperations.getAndDelete("passly:oauth:code:already-used")).thenReturn(null);

        Optional<PasslyAuthorizationCode> result = repository.consume("already-used");

        assertThat(result).isEmpty();
    }

    @Test
    void shouldCallGetAndDeleteForAtomicSingleUse() {
        // We're testing that getAndDelete is called (atomic operation)
        // Deserialization will fail but that's OK - we're testing the atomic behavior
        when(valueOperations.getAndDelete("passly:oauth:code:test-code"))
                .thenReturn("{\"test\":\"data\"}");

        try {
            repository.consume("test-code");
        } catch (IllegalStateException ex) {
            // Expected - JSON won't deserialize properly
        }

        // Verify getAndDelete was called (atomic single-use)
        verify(valueOperations).getAndDelete("passly:oauth:code:test-code");
    }

    @Test
    void shouldEnforceSingleUseSemanticsViaGetAndDelete() {
        // First call returns data, second returns null (already deleted)
        when(valueOperations.getAndDelete("passly:oauth:code:one-time"))
                .thenReturn("{\"data\":\"test\"}")
                .thenReturn(null);

        // First consume
        try {
            repository.consume("one-time");
        } catch (IllegalStateException ex) {
            // Expected
        }

        // Second consume
        Optional<PasslyAuthorizationCode> second = repository.consume("one-time");

        assertThat(second).isEmpty();  // Single-use enforced
        verify(valueOperations, times(2)).getAndDelete("passly:oauth:code:one-time");
    }

    @Test
    void shouldSerializeAndDeserializePasslyAuthorizationCodeWithSingleScope() throws Exception {
        UUID userId = UUID.randomUUID();
        Instant now = Instant.now();
        PasslyAuthorizationCode original = new PasslyAuthorizationCode(
                "code-single-scope",
                userId,
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                "openid",
                now,
                now.plusSeconds(120)
        );

        ObjectMapper objectMapper = new ObjectMapper();
        String json = objectMapper.writeValueAsString(original);

        assertThat(json).contains("\"scope\":\"openid\"");

        when(valueOperations.getAndDelete("passly:oauth:code:code-single-scope")).thenReturn(json);

        Optional<PasslyAuthorizationCode> result = repository.consume("code-single-scope");

        assertThat(result).isPresent();
        PasslyAuthorizationCode consumed = result.get();
        assertThat(consumed.code()).isEqualTo("code-single-scope");
        assertThat(consumed.scope()).isEqualTo("openid");
        assertThat(consumed.userId()).isEqualTo(userId);
    }

    @Test
    void shouldSerializeAndDeserializePasslyAuthorizationCodeWithMultipleScopes() throws Exception {
        UUID userId = UUID.randomUUID();
        Instant now = Instant.now();
        PasslyAuthorizationCode original = new PasslyAuthorizationCode(
                "code-multi-scope",
                userId,
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                "openid profile email",
                now,
                now.plusSeconds(120)
        );

        ObjectMapper objectMapper = new ObjectMapper();
        String json = objectMapper.writeValueAsString(original);

        assertThat(json).contains("\"scope\":\"openid profile email\"");

        when(valueOperations.getAndDelete("passly:oauth:code:code-multi-scope")).thenReturn(json);

        Optional<PasslyAuthorizationCode> result = repository.consume("code-multi-scope");

        assertThat(result).isPresent();
        assertThat(result.get().scope()).isEqualTo("openid profile email");
    }

    @Test
    void shouldSaveWithCorrectKeyPrefixAndTwoMinuteTtl() {
        PasslyAuthorizationCode code = new PasslyAuthorizationCode(
                "code-ttl-test",
                UUID.randomUUID(),
                "client-1",
                "https://example.com/callback",
                "challenge",
                "S256",
                "openid",
                Instant.now(),
                Instant.now().plusSeconds(120)
        );

        repository.save(code);

        verify(valueOperations).set(eq("passly:oauth:code:code-ttl-test"), anyString(), ttlCaptor.capture());
        assertThat(ttlCaptor.getValue()).isEqualTo(Duration.ofMinutes(2));
    }
}
