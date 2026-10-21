package com.eaglesoft.passly.demo_client;

import jakarta.servlet.http.HttpSession;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import com.eaglesoft.passly.demo_client.service.ResourceServerClient;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

@RestController
public class PasslyOAuthController {

    private static final String STATE_SESSION_KEY = "passly.oauth.state";
    private static final String VERIFIER_SESSION_KEY = "passly.oauth.verifier";

    private final PasslyProperties properties;
    private final RestClient restClient;
    private final JwtDecoder jwtDecoder;

    private final ResourceServerClient resourceServerClient;

    public PasslyOAuthController(
        PasslyProperties properties,
        ResourceServerClient resourceServerClient
    ) {
    this.properties = properties;
    this.resourceServerClient = resourceServerClient;
    this.restClient = RestClient.create();
    

    this.jwtDecoder = NimbusJwtDecoder
            .withJwkSetUri(properties.jwkSetUri())
            .build();
}

    @GetMapping("/")
    public String home(HttpSession session) {
        Object email = session.getAttribute("passly.email");
        Object name = session.getAttribute("passly.name");
        Object subject = session.getAttribute("passly.subject");

        if (subject == null) {
            return """
                    <h1>Passly Demo Client</h1>
                    <p>Not Authenticated</p>
                    <a href="/login/passly">Login with Passly</a>
                    """;
        }

        return """
                <h1>Passly Demo Client</h1>
                <h2>Authenticated Successfully!</h2>
                <ul>
                    <li><strong>Name:</strong> %s</li>
                    <li><strong>Email:</strong> %s</li>
                    <li><strong>Subject:</strong> %s</li>
                </ul>
                """.formatted(name, email, subject);
    }

    @GetMapping("/login/passly")
    public ResponseEntity<Void> login(HttpSession session) {
        String state = randomUrlSafe(32);
        String verifier = randomUrlSafe(64);
        String challenge = calculateS256(verifier);

        session.setAttribute(STATE_SESSION_KEY, state);
        session.setAttribute(VERIFIER_SESSION_KEY, verifier);

        String authorizationUrl = UriComponentsBuilder
                .fromUriString(properties.authorizationUri())
                .queryParam("response_type", "code")
                .queryParam("client_id", properties.clientId())
                .queryParam("redirect_uri", properties.redirectUri())
                .queryParam("scope", "profile email")
                .queryParam("state", state)
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256")
                .queryParam("provider", "google")
                .build()
                .encode()
                .toUriString();

        return ResponseEntity.status(302)
                .location(java.net.URI.create(authorizationUrl))
                .build();
    }

    @GetMapping("/login/oauth2/code/passly-demo")
    public String callback(
            @RequestParam String code,
            @RequestParam String state,
            HttpSession session
    ) {
        String expectedState =
                (String) session.getAttribute(STATE_SESSION_KEY);

        String verifier =
                (String) session.getAttribute(VERIFIER_SESSION_KEY);

        if (expectedState == null || !MessageDigest.isEqual(
                expectedState.getBytes(StandardCharsets.UTF_8),
                state.getBytes(StandardCharsets.UTF_8)
        )) {
            return "<h1>OAuth Error</h1><p>Invalid state.</p>";
        }

        if (verifier == null) {
            return "<h1>OAuth Error</h1><p>Missing code verifier.</p>";
        }

        TokenResponse tokenResponse = exchangeCode(code, verifier);

        String userinfo = 
                resourceServerClient.getUserInfo(tokenResponse.accessToken());

        Jwt jwt = jwtDecoder.decode(tokenResponse.accessToken());

        session.setAttribute("passly.subject", jwt.getSubject());
        session.setAttribute("passly.email", jwt.getClaimAsString("email"));
        session.setAttribute("passly.name", jwt.getClaimAsString("name"));

        session.removeAttribute(STATE_SESSION_KEY);
        session.removeAttribute(VERIFIER_SESSION_KEY);

        return """
                <h1>Passly OAuth2 E2E Success!</h1>

                <h2>Access Token Validated</h2>

                <ul>
                    <li><strong>Subject:</strong> %s</li>
                    <li><strong>Email:</strong> %s</li>
                    <li><strong>Name:</strong> %s</li>
                    <li><strong>Issuer:</strong> %s</li>
                    <li><strong>Client:</strong> %s</li>
                </ul>

                <p>Authorization Code → PKCE → Token → JWT validation succeeded.</p>

                <a href="/">Back to home</a>
                """.formatted(
                jwt.getSubject(),
                jwt.getClaimAsString("email"),
                jwt.getClaimAsString("name"),
                jwt.getIssuer(),
                jwt.getClaimAsString("client_id")
        );
    }

    private TokenResponse exchangeCode(String code, String verifier) {
        return restClient.post()
                .uri(properties.tokenUri())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body("grant_type=authorization_code"
                        + "&code=" + encode(code)
                        + "&redirect_uri=" + encode(properties.redirectUri())
                        + "&client_id=" + encode(properties.clientId())
                        + "&code_verifier=" + encode(verifier))
                .retrieve()
                .body(TokenResponse.class);
    }

    private static String calculateS256(String verifier) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            byte[] hash = digest.digest(
                    verifier.getBytes(StandardCharsets.US_ASCII)
            );

            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(hash);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to calculate PKCE challenge", e);
        }
    }

    private static String randomUrlSafe(int bytes) {
        byte[] random = new byte[bytes];
        new SecureRandom().nextBytes(random);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(random);
    }

    private static String encode(String value) {
        return java.net.URLEncoder
                .encode(value, StandardCharsets.UTF_8);
    }

    public record TokenResponse(
            String access_token,
            String token_type,
            long expires_in,
            String refresh_token
    ) {
        public String accessToken() {
            return access_token;
        }
    }
}
