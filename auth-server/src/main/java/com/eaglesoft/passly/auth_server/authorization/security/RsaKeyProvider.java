package com.eaglesoft.passly.auth_server.authorization.security;

import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

@Component
public class RsaKeyProvider {

    private static final int KEY_SIZE = 2048;

    private final SigningIdentity signingIdentity;

    public RsaKeyProvider(SigningKeyStore signingKeyStore) {
        this.signingIdentity = initializeSigningIdentity(signingKeyStore);
    }

    public KeyPair getKeyPair() {
        return signingIdentity.getKeyPair();
    }

    public java.security.PrivateKey getPrivateKey() {
        return signingIdentity.getKeyPair().getPrivate();
    }

    public java.security.PublicKey getPublicKey() {
        return signingIdentity.getKeyPair().getPublic();
    }

    public String getKeyId() {
        return signingIdentity.getKeyId();
    }

    private SigningIdentity initializeSigningIdentity(
            SigningKeyStore signingKeyStore
    ) {
        SigningIdentity existingIdentity = signingKeyStore.load();

        if (existingIdentity != null) {
            return existingIdentity;
        }

        SigningIdentity newIdentity = generateSigningIdentity();

        signingKeyStore.save(newIdentity);

        return newIdentity;
    }

    private SigningIdentity generateSigningIdentity() {
        try {
            KeyPairGenerator generator =
                    KeyPairGenerator.getInstance("RSA");

            generator.initialize(KEY_SIZE);

            KeyPair keyPair = generator.generateKeyPair();

            return new SigningIdentity(
                    keyPair,
                    UUID.randomUUID().toString()
            );

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "RSA algorithm is not available",
                    e
            );
        }
    }
}
