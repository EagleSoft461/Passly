package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.security.RsaKeyProvider;
import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import com.eaglesoft.passly.auth_server.domain.User;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwtTokenServiceImplTest {

    @Mock
    private RsaKeyProvider keyProvider;

    private JwtTokenServiceImpl jwtTokenService;
    private User testUser;
    private OAuthClient testClient;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        lenient().when(keyProvider.getKeyId()).thenReturn("key-id-123");
        lenient().when(keyProvider.getPrivateKey()).thenReturn((RSAPrivateKey) keyPair.getPrivate());

        jwtTokenService = new JwtTokenServiceImpl(keyProvider);

        UUID userId = UUID.randomUUID();
        testUser = mock(User.class);
        lenient().when(testUser.getId()).thenReturn(userId);
        lenient().when(testUser.getEmail()).thenReturn("user@example.com");

        testClient = new OAuthClient("test-client", "hash", "Test Client",
                List.of("https://example.com/callback"),
                List.of("openid", "profile", "email"));
    }

    @Test
    void shouldCreateJwtWithExactScopeOpenidProfile() throws Exception {
        String token = jwtTokenService.createAccessToken(testUser, testClient, "openid profile");

        assertThat(token).isNotBlank();

        SignedJWT signedJWT = SignedJWT.parse(token);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertThat(claims.getIssuer()).isEqualTo("https://passly.local");
        assertThat(claims.getSubject()).isEqualTo(testUser.getId().toString());
        assertThat(claims.getAudience()).containsExactly("test-client");
        assertThat(claims.getStringClaim("email")).isEqualTo("user@example.com");
        assertThat(claims.getStringClaim("scope")).isEqualTo("openid profile");
    }

    @Test
    void shouldCreateJwtWithOnlyEmailScope() throws Exception {
        String token = jwtTokenService.createAccessToken(testUser, testClient, "email");

        SignedJWT signedJWT = SignedJWT.parse(token);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertThat(claims.getStringClaim("scope")).isEqualTo("email");
    }

    @Test
    void shouldNotGrantAllRegisteredScopesWhenOnlyProfileIsRequested() throws Exception {
        // Client registered scopes: openid, profile, email
        // Requested scope: profile
        String token = jwtTokenService.createAccessToken(testUser, testClient, "profile");

        SignedJWT signedJWT = SignedJWT.parse(token);
        JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

        assertThat(claims.getStringClaim("scope")).isEqualTo("profile");
        assertThat(claims.getStringClaim("scope")).doesNotContain("openid");
        assertThat(claims.getStringClaim("scope")).doesNotContain("email");
    }

    @Test
    void shouldThrowExceptionWhenScopeIsNull() {
        assertThatThrownBy(() -> jwtTokenService.createAccessToken(testUser, testClient, null))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Scope cannot be null or blank when generating access token");
    }

    @Test
    void shouldThrowExceptionWhenScopeIsBlank() {
        assertThatThrownBy(() -> jwtTokenService.createAccessToken(testUser, testClient, "   "))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Scope cannot be null or blank when generating access token");
    }
}
