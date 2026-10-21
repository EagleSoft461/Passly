
package com.eaglesoft.passly.resource_server;

import com.eaglesoft.passly.resource_server.config.SecurityConfig;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.test.util.ReflectionTestUtils;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.*;

class JwtDecoderValidationTests {

    private RSAKey signingKey;
    private JwtDecoder decoder;
    private HttpServer jwksServer;

    private AtomicInteger jwksRequestCount;
    private AtomicReference<JWKSet> currentJwks;

    @BeforeEach
    void setUp() throws Exception {
        signingKey = generateKey("passly-test-key");

        jwksRequestCount = new AtomicInteger();
        currentJwks = new AtomicReference<>(
                new JWKSet(signingKey.toPublicJWK())
        );

        jwksServer = HttpServer.create(
                new InetSocketAddress("127.0.0.1", 0), 0
        );

        jwksServer.createContext("/jwks", exchange -> {
            jwksRequestCount.incrementAndGet();

            byte[] jwks = currentJwks.get()
                    .toString()
                    .getBytes(StandardCharsets.UTF_8);

            exchange.getResponseHeaders()
                    .set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, jwks.length);

            try (var output = exchange.getResponseBody()) {
                output.write(jwks);
            }
        });

        jwksServer.start();

        SecurityConfig config = new SecurityConfig();

        ReflectionTestUtils.setField(
                config,
                "jwkSetUri",
                "http://127.0.0.1:"
                        + jwksServer.getAddress().getPort() + "/jwks"
        );
        ReflectionTestUtils.setField(
                config, "expectedIssuer", "https://passly.local"
        );
        ReflectionTestUtils.setField(
                config, "expectedAudience", "passly-demo-client"
        );

        decoder = config.jwtDecoder();
    }

    @AfterEach
    void tearDown() {
        if (jwksServer != null) {
            jwksServer.stop(0);
        }
    }

    @Test
    void shouldAcceptValidSignedToken() throws Exception {
        Jwt jwt = decoder.decode(createToken(
                signingKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                futureExpiration()
        ));

        assertEquals("user-123", jwt.getSubject());
    }

    @Test
    void shouldRejectTokenSignedByUnknownKey() throws Exception {
        RSAKey unknownKey = generateKey("passly-test-key");

        String token = createToken(
                unknownKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                futureExpiration()
        );

        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    void shouldRejectWrongIssuer() throws Exception {
        String token = createToken(
                signingKey,
                "https://wrong-issuer.example",
                List.of("passly-demo-client"),
                futureExpiration()
        );

        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    void shouldRejectWrongAudience() throws Exception {
        String token = createToken(
                signingKey,
                "https://passly.local",
                List.of("another-client"),
                futureExpiration()
        );

        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    void shouldRejectExpiredToken() throws Exception {
        String token = createToken(
                signingKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                new Date(System.currentTimeMillis() - 60_000)
        );

        assertThrows(JwtException.class, () -> decoder.decode(token));
    }

    @Test
    void shouldReuseCachedJwksForKnownKey() throws Exception {
        String firstToken = createToken(
                signingKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                futureExpiration()
        );

        String secondToken = createToken(
                signingKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                futureExpiration()
        );

        decoder.decode(firstToken);
        int requestsAfterFirstDecode = jwksRequestCount.get();

        decoder.decode(secondToken);

        assertEquals(1, requestsAfterFirstDecode,
                "The first decode should fetch the JWKS once");
        assertEquals(1, jwksRequestCount.get(),
                "A known key should be served from the JWKS cache");
    }

    @Test
    void shouldRefreshJwksWhenTokenUsesUnknownKey() throws Exception {
        String initialToken = createToken(
                signingKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                futureExpiration()
        );

        decoder.decode(initialToken);
        int requestsBeforeRotation = jwksRequestCount.get();

        RSAKey rotatedKey = generateKey("passly-rotated-key");

        // Simulate publishing the new public key in JWKS.
        currentJwks.set(new JWKSet(List.of(
                signingKey.toPublicJWK(),
                rotatedKey.toPublicJWK()
        )));

        String rotatedToken = createToken(
                rotatedKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                futureExpiration()
        );

        Jwt jwt = decoder.decode(rotatedToken);

        assertEquals("user-123", jwt.getSubject());
        assertTrue(jwksRequestCount.get() > requestsBeforeRotation,
                "An unknown key should trigger a JWKS refresh");
    }

    private RSAKey generateKey(String keyId) throws Exception {
        return new RSAKeyGenerator(2048)
                .keyID(keyId)
                .generate();
    }

    private Date futureExpiration() {
        return new Date(System.currentTimeMillis() + 60_000);
    }

    private String createToken(
            RSAKey key,
            String issuer,
            List<String> audience,
            Date expiration
    ) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("user-123")
                .audience(audience)
                .issueTime(new Date())
                .expirationTime(expiration)
                .build();

        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(key.getKeyID())
                        .build(),
                claims
        );

        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }
}
