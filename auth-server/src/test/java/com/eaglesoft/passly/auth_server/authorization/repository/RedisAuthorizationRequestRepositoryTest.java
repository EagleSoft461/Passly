package com.eaglesoft.passly.auth_server.authorization.repository;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
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
import java.time.temporal.ChronoUnit;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/**
 * Unit tests for RedisAuthorizationRequestRepository.
 *
 * <p>Regression coverage for the Jackson 3 (tools.jackson.databind.ObjectMapper)
 * serialization fix: verifies that {@link AuthorizationRequest}, including its
 * {@code java.time.Instant expiresAt} field, survives a full JSON round-trip
 * without requiring any external module (JavaTimeModule is built into Jackson 3 core).
 *
 * <p>Tests use Mockito only — no Spring context needed.
 */
@ExtendWith(MockitoExtension.class)
class RedisAuthorizationRequestRepositoryTest {

    private static final String STATE = "test-state-abc123";
    private static final String KEY_PREFIX = "passly:oauth:authorization:";

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @Captor
    private ArgumentCaptor<String> jsonCaptor;

    @Captor
    private ArgumentCaptor<Duration> ttlCaptor;

    private RedisAuthorizationRequestRepository repository;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        repository = new RedisAuthorizationRequestRepository(redisTemplate, objectMapper);
    }

    /** Configures the Redis mock for tests that interact with Redis. */
    private void stubRedis() {
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    // -------------------------------------------------------------------------
    // Serialization regression — Instant round-trip (root cause fix)
    // -------------------------------------------------------------------------

    /**
     * Core regression: AuthorizationRequest with Instant fields must serialize and
     * deserialize without exception using tools.jackson.databind.ObjectMapper (Jackson 3).
     *
     * <p>Previously failed with Jackson 2 (com.fasterxml) new ObjectMapper():
     * InvalidDefinitionException: Java 8 date/time type java.time.Instant not supported by default.
     */
    @Test
    void shouldSerializeAndDeserializeAuthorizationRequestWithInstantField() throws Exception {
        // Instant truncated to millis — JSON round-trip preserves millis precision
        Instant expiresAt = Instant.now().plus(5, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS);

        AuthorizationRequest request = new AuthorizationRequest(
                STATE,
                "my-client",
                "https://client.example.com/callback",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "S256",
                "google",
                expiresAt
        );

        // Serialize
        String json = objectMapper.writeValueAsString(request);

        // Sanity: JSON must not be empty and must contain the state
        assertThat(json).isNotBlank().contains(STATE);

        // Deserialize
        AuthorizationRequest deserialized = objectMapper.readValue(json, AuthorizationRequest.class);

        assertThat(deserialized.state()).isEqualTo(request.state());
        assertThat(deserialized.clientId()).isEqualTo(request.clientId());
        assertThat(deserialized.redirectUri()).isEqualTo(request.redirectUri());
        assertThat(deserialized.codeChallenge()).isEqualTo(request.codeChallenge());
        assertThat(deserialized.codeChallengeMethod()).isEqualTo(request.codeChallengeMethod());
        assertThat(deserialized.provider()).isEqualTo(request.provider());
        // Instant round-trip — exact millisecond equality
        assertThat(deserialized.expiresAt()).isEqualTo(expiresAt);
    }

    // -------------------------------------------------------------------------
    // save() — Redis interaction
    // -------------------------------------------------------------------------

    @Test
    void shouldSaveSerializedJsonToRedisWithCorrectKeyAndTtl() {
        stubRedis();
        Instant expiresAt = Instant.now().plus(5, ChronoUnit.MINUTES);
        AuthorizationRequest request = sampleRequest(expiresAt);

        repository.save(request);

        verify(valueOperations).set(
                eq(KEY_PREFIX + STATE),
                jsonCaptor.capture(),
                ttlCaptor.capture()
        );

        assertThat(jsonCaptor.getValue()).contains(STATE);
        assertThat(ttlCaptor.getValue()).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void shouldUseStateAsRedisKey() {
        stubRedis();
        AuthorizationRequest request = sampleRequest(Instant.now().plusSeconds(300));

        repository.save(request);

        verify(valueOperations).set(eq(KEY_PREFIX + STATE), any(), any(Duration.class));
    }

    // -------------------------------------------------------------------------
    // consume() — single-use atomicity via getAndDelete
    // -------------------------------------------------------------------------

    @Test
    void shouldReturnEmptyWhenStateNotFound() {
        stubRedis();
        when(valueOperations.getAndDelete(KEY_PREFIX + "missing-state")).thenReturn(null);

        Optional<AuthorizationRequest> result = repository.consume("missing-state");

        assertThat(result).isEmpty();
    }

    @Test
    void shouldReturnDeserializedRequestOnConsume() throws Exception {
        stubRedis();
        AuthorizationRequest original = sampleRequest(
                Instant.now().plus(5, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS)
        );
        String json = objectMapper.writeValueAsString(original);
        when(valueOperations.getAndDelete(KEY_PREFIX + STATE)).thenReturn(json);

        Optional<AuthorizationRequest> result = repository.consume(STATE);

        assertThat(result).isPresent();
        AuthorizationRequest consumed = result.get();
        assertThat(consumed.state()).isEqualTo(original.state());
        assertThat(consumed.clientId()).isEqualTo(original.clientId());
        assertThat(consumed.expiresAt()).isEqualTo(original.expiresAt());
    }

    @Test
    void shouldUseGetAndDeleteForAtomicSingleUseSemantics() {
        stubRedis();
        when(valueOperations.getAndDelete(KEY_PREFIX + STATE))
                .thenReturn(null);

        repository.consume(STATE);

        // getAndDelete must be called — not get() followed by delete()
        verify(valueOperations).getAndDelete(KEY_PREFIX + STATE);
        verify(valueOperations, never()).get(any());
    }

    @Test
    void shouldReturnEmptyOnSecondConsumeAfterSingleUse() throws Exception {
        stubRedis();
        AuthorizationRequest original = sampleRequest(
                Instant.now().plus(5, ChronoUnit.MINUTES).truncatedTo(ChronoUnit.MILLIS)
        );
        String json = objectMapper.writeValueAsString(original);

        when(valueOperations.getAndDelete(KEY_PREFIX + STATE))
                .thenReturn(json)   // first call: data present
                .thenReturn(null);  // second call: already deleted

        // First consume
        Optional<AuthorizationRequest> first = repository.consume(STATE);
        assertThat(first).isPresent();

        // Second consume must be empty — single-use enforced
        Optional<AuthorizationRequest> second = repository.consume(STATE);
        assertThat(second).isEmpty();

        verify(valueOperations, times(2)).getAndDelete(KEY_PREFIX + STATE);
    }

    // -------------------------------------------------------------------------
    // Helper
    // -------------------------------------------------------------------------

    private AuthorizationRequest sampleRequest(Instant expiresAt) {
        return new AuthorizationRequest(
                STATE,
                "my-client",
                "https://client.example.com/callback",
                "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "S256",
                "google",
                expiresAt
        );
    }
}
