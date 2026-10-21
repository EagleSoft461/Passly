package com.eaglesoft.passly.resource_server;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ResourceServerEndToEndSecurityTests {

    private static RSAKey signingKey;
    private static HttpServer jwksServer;
    private static AtomicInteger jwksRequestCount;
    private static AtomicReference<JWKSet> currentJwks;

    @Autowired
    private MockMvc mockMvc;

    @BeforeAll
    static void startJwksServer() throws Exception {
        signingKey = new RSAKeyGenerator(2048)
                .keyID("passly-test-key")
                .generate();

        jwksRequestCount = new AtomicInteger();
        currentJwks = new AtomicReference<>(
                new JWKSet(signingKey.toPublicJWK())
        );

        jwksServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        jwksServer.createContext("/jwks", exchange -> {
            jwksRequestCount.incrementAndGet();
            byte[] jwksBytes = currentJwks.get().toString().getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, jwksBytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(jwksBytes);
            }
        });
        jwksServer.start();
    }

    @AfterAll
    static void stopJwksServer() {
        if (jwksServer != null) {
            jwksServer.stop(0);
        }
    }

    @DynamicPropertySource
    static void configureProperties(DynamicPropertyRegistry registry) {
        registry.add(
                "spring.security.oauth2.resourceserver.jwt.jwk-set-uri",
                () -> "http://127.0.0.1:" + jwksServer.getAddress().getPort() + "/jwks"
        );
        registry.add("passly.security.jwt.issuer", () -> "https://passly.local");
        registry.add("passly.security.jwt.audience", () -> "passly-demo-client");
    }

    @Test
    void shouldAcceptValidBearerTokenForMeEndpoint() throws Exception {
        String token = createToken(
                signingKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                "openid profile email",
                futureExpiration()
        );

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("user-123"))
                .andExpect(jsonPath("$.issuer").value("https://passly.local"))
                .andExpect(jsonPath("$.audience[0]").value("passly-demo-client"))
                .andExpect(jsonPath("$.scopes", org.hamcrest.Matchers.containsInAnyOrder("openid", "profile", "email")));
    }

    @Test
    void shouldAcceptValidBearerTokenWithProfileScopeForUserInfo() throws Exception {
        String token = createToken(
                signingKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                "profile",
                futureExpiration()
        );

        mockMvc.perform(get("/api/userinfo").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(content().string("Authenticated user: user-123"));
    }

    @Test
    void shouldRejectBearerTokenWithoutProfileScopeForUserInfo() throws Exception {
        String token = createToken(
                signingKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                "email",
                futureExpiration()
        );

        mockMvc.perform(get("/api/userinfo").header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    @Test
    void shouldRejectBearerTokenWithInvalidSignature() throws Exception {
        RSAKey untrustedKey = new RSAKeyGenerator(2048)
                .keyID("untrusted-key")
                .generate();

        String token = createToken(
                untrustedKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                "profile",
                futureExpiration()
        );

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectExpiredBearerToken() throws Exception {
        String token = createToken(
                signingKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                "profile",
                new Date(System.currentTimeMillis() - 60_000)
        );

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectBearerTokenWithWrongIssuer() throws Exception {
        String token = createToken(
                signingKey,
                "https://malicious-issuer.example",
                List.of("passly-demo-client"),
                "profile",
                futureExpiration()
        );

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectBearerTokenWithWrongAudience() throws Exception {
        String token = createToken(
                signingKey,
                "https://passly.local",
                List.of("wrong-client"),
                "profile",
                futureExpiration()
        );

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldRejectMissingBearerToken() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldVerifyJwksCachingAcrossMultipleResourceRequests() throws Exception {
        String token = createToken(
                signingKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                "profile",
                futureExpiration()
        );

        // Make first request
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        int countAfterFirst = jwksRequestCount.get();

        // Make second and third requests
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        // Verify request count did not increase (JWKS was reused from cache)
        assertEquals(countAfterFirst, jwksRequestCount.get(),
                "Resource requests should reuse cached JWKS and not call back to Passly");
    }

    @Test
    void shouldHandleKeyRotationWhenTokenPresentsNewKeyId() throws Exception {
        int initialCount = jwksRequestCount.get();

        RSAKey rotatedKey = new RSAKeyGenerator(2048)
                .keyID("passly-rotated-key")
                .generate();

        // Passly publishes new key to JWKS
        currentJwks.set(new JWKSet(List.of(
                signingKey.toPublicJWK(),
                rotatedKey.toPublicJWK()
        )));

        String rotatedToken = createToken(
                rotatedKey,
                "https://passly.local",
                List.of("passly-demo-client"),
                "profile",
                futureExpiration()
        );

        mockMvc.perform(get("/api/me").header("Authorization", "Bearer " + rotatedToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("user-123"));

        assertTrue(jwksRequestCount.get() > initialCount,
                "An unknown key ID should trigger a JWKS cache refresh to support key rotation");
    }

    private Date futureExpiration() {
        return new Date(System.currentTimeMillis() + 60_000);
    }

    private String createToken(
            RSAKey key,
            String issuer,
            List<String> audience,
            String scope,
            Date expiration
    ) throws Exception {
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject("user-123")
                .audience(audience)
                .claim("scope", scope)
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
