package com.eaglesoft.passly.auth_server.authorization.security;

import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

/**
 * Provides the RSA key pair used by Passly for RS256 JWT signing.
 *
 * The private key is kept inside the authorization server and is used
 * exclusively for signing access tokens.
 *
 * The public key is exposed through the JWKS endpoint so resource servers
 * can validate JWT signatures locally.
 */
@Component
public class RsaKeyProvider {

    private static final int KEY_SIZE = 2048;

    private final KeyPair keyPair;
    private final String keyId;

    public RsaKeyProvider() {
        this.keyPair = generateKeyPair();
        this.keyId = UUID.randomUUID().toString();
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }

    public java.security.PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public java.security.PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    /**
     * Returns the identifier of the currently active signing key.
     *
     * This value will be placed in the JWT "kid" header and exposed
     * through the JWKS endpoint.
     */
    public String getKeyId() {
        return keyId;
    }

    private KeyPair generateKeyPair() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_SIZE);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "RSA algorithm is not available", e);
        }
    }
}
