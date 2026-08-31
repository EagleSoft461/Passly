package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;

import java.util.Optional;

public interface AuthorizationRequestService {

    void save(AuthorizationRequest request);

    Optional<AuthorizationRequest> consume(String state);
}
