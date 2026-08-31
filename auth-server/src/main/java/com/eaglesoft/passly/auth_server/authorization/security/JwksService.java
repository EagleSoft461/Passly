package com.eaglesoft.passly.auth_server.authorization.security;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPublicKey;

@Service
public class JwksService {

    private final RsaKeyProvider keyProvider;

    public JwksService(RsaKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    /**
     * Returns the public RSA key as a JWKS JSON representation.
     *
     * The private key is never exposed.
     */
    public String getJwks() {
        RSAPublicKey publicKey =
                (RSAPublicKey) keyProvider.getPublicKey();

        JWK jwk = new RSAKey.Builder(publicKey)
                .keyID(keyProvider.getKeyId())
                .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .build();

        return new JWKSet(jwk).toString();
    }
}
