package com.eaglesoft.passly.auth_server.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "linked_accounts",
        uniqueConstraints = @UniqueConstraint(columnNames = {"provider", "provider_user_id"})
)
public class LinkedAccount {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private Provider provider;

    @Column(name = "provider_user_id", nullable = false)
    private String providerUserId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    protected LinkedAccount() {
    }

    public LinkedAccount(User user, Provider provider, String providerUserId) {
        this.user = user;
        this.provider = provider;
        this.providerUserId = providerUserId;
    }

    public UUID getId() { return id; }
    public User getUser() { return user; }
    public Provider getProvider() { return provider; }
    public String getProviderUserId() { return providerUserId; }
    public Instant getCreatedAt() { return createdAt; }

    public enum Provider {
        GOOGLE, GITHUB
    }
}
