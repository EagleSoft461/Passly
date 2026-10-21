package com.eaglesoft.passly.resource_server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

import java.util.List;

@Configuration
public class SecurityConfig {

    @Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}")
    private String jwkSetUri;

    @Value("${passly.security.jwt.issuer}")
    private String expectedIssuer;

    @Value("${passly.security.jwt.audience}")
    private String expectedAudience;

    /**
     * Custom JwtDecoder that validates:
     *   1. RS256 signature via JWKS endpoint (jwk-set-uri)
     *   2. Issuer claim matches expected value
     *   3. Audience claim contains the expected resource-server audience
     *   4. Expiration / not-before timestamps (via default validators)
     *
     * This replaces Spring's issuer-uri auto-discovery, which would attempt
     * OIDC discovery against a non-existent /.well-known/openid-configuration
     * endpoint (Passly does not implement OIDC in v0.2.0).
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();

        // Default validators: timestamp (exp, nbf) + issuer
        OAuth2TokenValidator<Jwt> defaultValidators =
                JwtValidators.createDefaultWithIssuer(expectedIssuer);

        // Audience validator: token must be intended for this resource server
        OAuth2TokenValidator<Jwt> audienceValidator = new JwtClaimValidator<List<String>>(
                "aud",
                aud -> aud != null && aud.contains(expectedAudience)
        );

        OAuth2TokenValidator<Jwt> combinedValidators =
                new DelegatingOAuth2TokenValidator<>(defaultValidators, audienceValidator);

        decoder.setJwtValidator(combinedValidators);

        return decoder;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/userinfo").hasAuthority("SCOPE_profile")
                        .requestMatchers("/api/me").authenticated()
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.decoder(jwtDecoder()))
                );

        return http.build();
    }
}
