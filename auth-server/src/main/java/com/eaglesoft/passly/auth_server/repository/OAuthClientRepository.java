package com.eaglesoft.passly.auth_server.repository;

import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, String> {

    @EntityGraph(attributePaths = "redirectUris")
    Optional<OAuthClient> findById(String clientId);
}
