package com.eaglesoft.passly.auth_server.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Minimal Spring Security configuration for the Passly authorization server.
 *
 * Design constraints (all RFC-justified):
 *
 *   1. CSRF disabled globally.
 *      The auth server exposes machine-to-machine API endpoints (token endpoint, JWKS)
 *      and browser-initiated redirect endpoints (authorize, Google callback).
 *      None of these are browser-form POST actions protected by the CSRF cookie pattern.
 *      - Token endpoint: programmatic API; PKCE + client_id is the integrity guarantee
 *        (RFC 6749 §2.3.1, RFC 9700 §4.3).
 *      - Authorize endpoint: GET only; CSRF does not apply to GET.
 *      - Callback endpoint: GET only (OAuth2 redirect); CSRF does not apply.
 *      - JWKS endpoint: read-only public GET.
 *      Re-enabling CSRF would break any standard OAuth2 client calling the token endpoint.
 *
 *   2. Sessions: STATELESS.
 *      The authorization server does not issue or consume HTTP sessions.
 *      Token state is tracked via the database (refresh tokens) and Redis (auth codes, state).
 *      RFC 6749 §4.1.3 requires token requests to be self-contained; no session needed.
 *
 *   3. Public paths — exactly the four OAuth2/OIDC endpoints defined in the server:
 *      - GET  /oauth2/authorize          — RFC 6749 §4.1.1 (authorization endpoint)
 *      - POST /oauth2/token              — RFC 6749 §3.2  (token endpoint)
 *      - GET  /login/oauth2/code/google  — OAuth2 callback from Google
 *      - GET  /.well-known/jwks.json     — RFC 7517 §5 (public key set)
 *      All other paths require authentication (safe default).
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF disabled — machine-to-machine token endpoint; PKCE provides integrity.
                .csrf(AbstractHttpConfigurer::disable)

                // Stateless — no HTTP session; all auth state is in tokens + DB/Redis.
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth -> auth
                        // RFC 6749 §4.1.1 — authorization endpoint
                        .requestMatchers("/oauth2/authorize").permitAll()
                        // RFC 6749 §3.2 — token endpoint
                        .requestMatchers("/oauth2/token").permitAll()
                        // OAuth2 callback from Google (handled by GoogleCallbackController)
                        .requestMatchers("/login/oauth2/code/google").permitAll()
                        // RFC 7517 §5 — JWKS public key set
                        .requestMatchers("/.well-known/jwks.json").permitAll()
                        .requestMatchers("/error").permitAll()
                        // All other paths are protected (safe default)
                        .anyRequest().authenticated()
                );

        return http.build();
    }
}
