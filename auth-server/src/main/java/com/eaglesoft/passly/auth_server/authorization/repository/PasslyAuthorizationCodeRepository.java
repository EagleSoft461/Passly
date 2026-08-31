package com.eaglesoft.passly.auth_server.authorization.repository;

import com.eaglesoft.passly.auth_server.authorization.model.PasslyAuthorizationCode;

import java.util.Optional;

/**
 * Repository for Passly authorization codes.
 * Codes are short-lived, single-use tokens stored in Redis.
 */
public interface PasslyAuthorizationCodeRepository {

    /**
     * Saves the authorization code with TTL.
     * The code will automatically expire after the configured duration (2 minutes).
     *
     * @param code The authorization code to save
     */
    void save(PasslyAuthorizationCode code);

    /**
     * Consumes (retrieves and deletes) the authorization code.
     * This is an atomic operation ensuring single-use semantics.
     * Once consumed, the code is deleted and cannot be used again.
     *
     * @param code The authorization code string
     * @return The authorization code details if found and not expired, empty otherwise
     */
    Optional<PasslyAuthorizationCode> consume(String code);
}
