package com.eaglesoft.passly.auth_server.repository;

import com.eaglesoft.passly.auth_server.domain.LinkedAccount;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface LinkedAccountRepository extends JpaRepository<LinkedAccount, UUID> {

    Optional<LinkedAccount> findByProviderAndProviderUserId(
            LinkedAccount.Provider provider, String providerUserId);
}
