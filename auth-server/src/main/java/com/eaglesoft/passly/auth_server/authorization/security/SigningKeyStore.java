package com.eaglesoft.passly.auth_server.authorization.security;

public interface SigningKeyStore {
    SigningIdentity load();

    void save(SigningIdentity identity);
}
