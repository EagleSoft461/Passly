package com.eaglesoft.passly.auth_server.authorization.repository;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import tools.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.util.Optional;

@Repository
public class RedisAuthorizationRequestRepository implements AuthorizationRequestRepository {

    private static final String KEY_PREFIX = "passly:oauth:authorization:";
    private static final Duration TTL = Duration.ofMinutes(5);

    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;

    public RedisAuthorizationRequestRepository(
            StringRedisTemplate redisTemplate,
            ObjectMapper objectMapper
    ) {
        this.redisTemplate = redisTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public void save(AuthorizationRequest request) {
        try {
            String json = objectMapper.writeValueAsString(request);

            redisTemplate.opsForValue()
                    .set(key(request.state()), json, TTL);

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to serialize AuthorizationRequest",
                    e
            );
        }
    }

    @Override
    public Optional<AuthorizationRequest> consume(String state) {
        String json = redisTemplate.opsForValue()
                .getAndDelete(key(state));

        if (json == null) {
            return Optional.empty();
        }

        try {
            return Optional.of(
                    objectMapper.readValue(
                            json,
                            AuthorizationRequest.class
                    )
            );
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to deserialize AuthorizationRequest",
                    e
            );
        }
    }

    private String key(String state) {
        return KEY_PREFIX + state;
    }
}
