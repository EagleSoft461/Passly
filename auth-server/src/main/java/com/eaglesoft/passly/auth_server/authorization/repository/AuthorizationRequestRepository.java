package com.eaglesoft.passly.auth_server.authorization.repository;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;

import java.util.Optional;

public interface AuthorizationRequestRepository {

    void save(AuthorizationRequest request);

    Optional<AuthorizationRequest> consume(String state);
}
