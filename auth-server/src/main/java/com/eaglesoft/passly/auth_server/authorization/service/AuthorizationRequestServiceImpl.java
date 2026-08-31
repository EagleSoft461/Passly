package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import com.eaglesoft.passly.auth_server.authorization.repository.AuthorizationRequestRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthorizationRequestServiceImpl implements AuthorizationRequestService {

    private final AuthorizationRequestRepository repository;

    public AuthorizationRequestServiceImpl(AuthorizationRequestRepository repository) {
        this.repository = repository;
    }

    @Override
    public void save(AuthorizationRequest request) {
        repository.save(request);
    }

    @Override
    public Optional<AuthorizationRequest> consume(String state) {
        return repository.consume(state);
    }
}
