package com.eaglesoft.passly.auth_server.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.List;

@Entity
@Table(name = "oauth_clients")
public class OAuthClient {

    @Id
    @Column(name = "client_id", length = 100)
    private String clientId;

    @Column(name = "client_secret_hash", nullable = false)
    private String clientSecretHash;

    @Column(name = "client_name", nullable = false)
    private String clientName;

    @Column(nullable = false)
    private boolean enabled = true;

    @ElementCollection
    @CollectionTable(name = "oauth_client_redirect_uris", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "redirect_uri")
    private List<String> redirectUris;

    @ElementCollection
    @CollectionTable(name = "oauth_client_scopes", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "scope")
    private List<String> scopes;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    protected OAuthClient() {
    }

    public OAuthClient(String clientId, String clientSecretHash, String clientName,
                       List<String> redirectUris, List<String> scopes) {
        this.clientId = clientId;
        this.clientSecretHash = clientSecretHash;
        this.clientName = clientName;
        this.redirectUris = redirectUris;
        this.scopes = scopes;
        this.enabled = true;
    }

    public boolean isEnabled() { return enabled; }
    public String getClientId() { return clientId; }
    public String getClientSecretHash() { return clientSecretHash; }
    public String getClientName() { return clientName; }
    public List<String> getRedirectUris() { return redirectUris; }
    public List<String> getScopes() { return scopes; }
    public Instant getCreatedAt() { return createdAt; }
}
