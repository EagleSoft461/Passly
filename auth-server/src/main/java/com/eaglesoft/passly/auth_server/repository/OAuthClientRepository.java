package com.eaglesoft.passly.auth_server.repository;

import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OAuthClientRepository extends JpaRepository<OAuthClient, String> {
    // clientId zaten @Id, findById(clientId) JpaRepository'den geliyor — ekstra metod gerekmiyor
}
