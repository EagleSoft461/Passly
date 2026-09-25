package com.eaglesoft.passly.auth_server.authorization.security;

import java.security.KeyPair;

public class SigningIdentity {

    private final KeyPair keyPair;
    private final String keyId;

    public SigningIdentity(KeyPair keyPair, String keyId) {
        this.keyPair = keyPair;
        this.keyId = keyId;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public String getKeyId() {
        return keyId;
    }
}
