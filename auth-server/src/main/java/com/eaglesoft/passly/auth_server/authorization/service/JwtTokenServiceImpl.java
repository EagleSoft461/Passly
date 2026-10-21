package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.security.RsaKeyProvider;
import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import com.eaglesoft.passly.auth_server.domain.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.security.interfaces.RSAPrivateKey;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

@Service
public class JwtTokenServiceImpl implements JwtTokenService {

    private static final long ACCESS_TOKEN_TTL_SECONDS = 900;

    private final RsaKeyProvider keyProvider;

    public JwtTokenServiceImpl(RsaKeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @Override
    public String createAccessToken(User user, OAuthClient client, String scope) {
        if (scope == null || scope.isBlank()) {
            throw new IllegalArgumentException("Scope cannot be null or blank when generating access token");
        }

        Instant now = Instant.now();

        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer("https://passly.local")
                .subject(user.getId().toString())
                .audience(client.getClientId())
                .issueTime(Date.from(now))
                .expirationTime(
                        Date.from(now.plusSeconds(ACCESS_TOKEN_TTL_SECONDS))
                )
                .jwtID(UUID.randomUUID().toString())
                .claim("email", user.getEmail())
                .claim("scope", scope.trim())
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID(keyProvider.getKeyId())
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claims);

        try {
            signedJWT.sign(new RSASSASigner((RSAPrivateKey) keyProvider.getPrivateKey()));
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException(
                    "Failed to sign access token",
                    e
            );
        }
    }
}
