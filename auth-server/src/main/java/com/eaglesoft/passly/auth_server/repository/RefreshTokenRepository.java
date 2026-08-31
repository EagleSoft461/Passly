package com.eaglesoft.passly.auth_server.repository;

import com.eaglesoft.passly.auth_server.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findAllByUser_IdAndRevokedAtIsNull(UUID userId);

    List<RefreshToken> findAllByTokenFamilyIdAndRevokedAtIsNull(UUID tokenFamilyId);
}
