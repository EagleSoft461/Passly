package com.eaglesoft.passly.auth_server.authorization.repository;

import com.eaglesoft.passly.auth_server.authorization.model.PasslyAuthorizationCode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Optional;

/**
 * Redis-based implementation of PasslyAuthorizationCodeRepository.
 * Uses atomic getAndDelete() operation for single-use consumption.
 */
@Repository
public class RedisPasslyAuthorizationCodeRepository implements PasslyAuthorizationCodeRepository {

    private static final String KEY_PREFIX = "passly:oauth:code:";
    private static final Duration TTL = Duration.ofMinutes(2);

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper = new ObjectMapper();

    public RedisPasslyAuthorizationCodeRepository(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void save(PasslyAuthorizationCode code) {
        try {
            String json = objectMapper.writeValueAsString(code);
            redisTemplate.opsForValue().set(key(code.code()), json, TTL);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to serialize PasslyAuthorizationCode", e);
        }
    }

    @Override
    public Optional<PasslyAuthorizationCode> consume(String code) {
        String json = redisTemplate.opsForValue().getAndDelete(key(code));
        if (json == null) {
            return Optional.empty();
        }
        try {
            return Optional.of(objectMapper.readValue(json, PasslyAuthorizationCode.class));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to deserialize PasslyAuthorizationCode", e);
        }
    }

    private String key(String code) {
        return KEY_PREFIX + code;
    }
}
