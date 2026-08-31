package com.eaglesoft.passly.auth_server.domain;

import jakarta.persistence.*;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "client_id", nullable = false)
    private OAuthClient client;

    @Column(name = "token_hash", nullable = false, unique = true)
    private String tokenHash;

    @Column(name = "token_family_id", nullable = false)
    private UUID tokenFamilyId;

    @Column(name = "replaced_by")
    private UUID replacedBy;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    protected RefreshToken() {
    }

    public RefreshToken(
            User user,
            OAuthClient client,
            String tokenHash,
            UUID tokenFamilyId,
            Instant expiresAt
    ) {
        this.user = user;
        this.client = client;
        this.tokenHash = tokenHash;
        this.tokenFamilyId = tokenFamilyId;
        this.expiresAt = expiresAt;
    }

    public boolean isRevoked() {
        return revokedAt != null;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public void revoke() {
        if (!isRevoked()) {
            this.revokedAt = Instant.now();
        }
    }

    public void markReplacedBy(UUID replacementTokenId) {
        this.replacedBy = replacementTokenId;
        this.revokedAt = Instant.now();
    }

    public UUID getId() {
        return id;
    }

    public User getUser() {
        return user;
    }

    public OAuthClient getClient() {
        return client;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public UUID getTokenFamilyId() {
        return tokenFamilyId;
    }

    public UUID getReplacedBy() {
        return replacedBy;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }
}
