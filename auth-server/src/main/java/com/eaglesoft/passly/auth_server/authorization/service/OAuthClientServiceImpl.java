package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.InvalidClientException;
import com.eaglesoft.passly.auth_server.authorization.exception.InvalidRedirectUriException;
import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import com.eaglesoft.passly.auth_server.repository.OAuthClientRepository;
import org.springframework.stereotype.Service;

@Service
public class OAuthClientServiceImpl implements OAuthClientService {

    private final OAuthClientRepository repository;

    public OAuthClientServiceImpl(OAuthClientRepository repository) {
        this.repository = repository;
    }

    @Override
    public OAuthClient validateClientAndRedirectUri(String clientId, String redirectUri) {
        OAuthClient client = repository.findById(clientId)
                .orElseThrow(() -> new InvalidClientException("Unknown client_id: " + clientId));

        if (!client.isEnabled()) {
            throw new InvalidClientException("Client is disabled: " + clientId);
        }

        // Exact match only — no wildcard/prefix matching (ADR-001, API Contract)
        boolean redirectUriRegistered = client.getRedirectUris().contains(redirectUri);
        if (!redirectUriRegistered) {
            throw new InvalidRedirectUriException(
                    "redirect_uri is not registered for client " + clientId);
        }

        return client;
    }
}
