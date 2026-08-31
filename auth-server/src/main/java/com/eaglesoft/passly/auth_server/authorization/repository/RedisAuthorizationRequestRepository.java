package com.eaglesoft.passly.auth_server.authorization.repository;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Optional;

@Repository
public class RedisAuthorizationRequestRepository implements AuthorizationRequestRepository {

    private static final String KEY_PREFIX = "passly:oauth:authorization:";
    private static final Duration TTL = Duration.ofMinutes(5); // Decision 7

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();
    // Bilinçli olarak Spring'in global JSON mapper'ından (Jackson 3'e geçti,
    // Spring Boot 4) bağımsız tutuyoruz — bu, Redis'teki iç saklama formatımız,
    // uygulamanın dışa açık HTTP JSON sözleşmesiyle ilgisi yok.

    public RedisAuthorizationRequestRepository(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void save(AuthorizationRequest request) {
        try {
            String json = objectMapper.writeValueAsString(request);
            redisTemplate.opsForValue().set(key(request.state()), json, TTL);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize AuthorizationRequest", e);
        }
    }

    @Override
    public Optional<AuthorizationRequest> consume(String state) {
        String json = redisTemplate.opsForValue().getAndDelete(key(state));
        if (json == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(objectMapper.readValue(json, AuthorizationRequest.class));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize AuthorizationRequest", e);
        }
    }

    private String key(String state) {
        return KEY_PREFIX + state;
    }
}
