package com.eaglesoft.passly.auth_server.authorization.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Creates Passly access tokens as RS256-signed JWTs.
 *
 * The private RSA key never leaves the authorization server.
 * Resource servers validate the resulting JWT using the public key
 * exposed through the JWKS endpoint.
 */
@Service
public class JwtService {

    private static final String ISSUER = "passly";
    private static final Duration ACCESS_TOKEN_TTL = Duration.ofMinutes(15);

    private final RsaKeyProvider keyProvider;

    public JwtService(RsaKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    /**
     * Creates a short-lived RS256 access token for the given user and client.
     *
     * @param userId authenticated Passly user
     * @param clientId OAuth client receiving the token
     * @return signed JWT
     */
    public String createAccessToken(UUID userId, String clientId) {
        Instant now = Instant.now();
        Instant expiresAt = now.plus(ACCESS_TOKEN_TTL);

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(ISSUER)
                .subject(userId.toString())
                .audience(clientId)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID(UUID.randomUUID().toString())
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(keyProvider.getKeyId())
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);

        try {
            JWSSigner signer = new RSASSASigner(keyProvider.getPrivateKey());
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(
                    "Failed to sign access token", e);
        }
    }

    public long getAccessTokenExpiresIn() {
        return ACCESS_TOKEN_TTL.toSeconds();
    }
}
