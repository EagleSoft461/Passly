package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.TokenExchangeException;
import com.eaglesoft.passly.auth_server.authorization.model.PasslyAuthorizationCode;
import com.eaglesoft.passly.auth_server.authorization.model.RotatedRefreshToken;
import com.eaglesoft.passly.auth_server.authorization.model.TokenRequest;
import com.eaglesoft.passly.auth_server.authorization.model.TokenResponse;
import com.eaglesoft.passly.auth_server.authorization.repository.PasslyAuthorizationCodeRepository;
import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import com.eaglesoft.passly.auth_server.domain.User;
import com.eaglesoft.passly.auth_server.repository.OAuthClientRepository;
import com.eaglesoft.passly.auth_server.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.util.Base64;
import java.util.Optional;

@Service
public class TokenServiceImpl implements TokenService {

    private static final String GRANT_TYPE_AUTHORIZATION_CODE =
            "authorization_code";

    private static final String GRANT_TYPE_REFRESH_TOKEN =
            "refresh_token";

    private final PasslyAuthorizationCodeRepository authorizationCodeRepository;
    private final OAuthClientRepository oauthClientRepository;
    private final UserRepository userRepository;
    private final JwtTokenService jwtTokenService;
    private final RefreshTokenService refreshTokenService;

    public TokenServiceImpl(
            PasslyAuthorizationCodeRepository authorizationCodeRepository,
            OAuthClientRepository oauthClientRepository,
            UserRepository userRepository,
            JwtTokenService jwtTokenService,
            RefreshTokenService refreshTokenService
    ) {
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.oauthClientRepository = oauthClientRepository;
        this.userRepository = userRepository;
        this.jwtTokenService = jwtTokenService;
        this.refreshTokenService = refreshTokenService;
    }

    @Override
    @Transactional
    public TokenResponse exchange(TokenRequest request) {

        if (request == null) {
            throw new TokenExchangeException(
                    "invalid_request",
                    "Token request cannot be null"
            );
        }

        if (GRANT_TYPE_AUTHORIZATION_CODE.equals(request.grantType())) {
            return exchangeAuthorizationCode(request);
        }

        if (GRANT_TYPE_REFRESH_TOKEN.equals(request.grantType())) {
            return exchangeRefreshToken(request);
        }

        throw new TokenExchangeException(
                "unsupported_grant_type",
                "Unsupported grant_type: " + request.grantType()
        );
    }

    private TokenResponse exchangeAuthorizationCode(
            TokenRequest request
    ) {

        requireText(request.code(), "code", "invalid_request");
        requireText(request.clientId(), "client_id", "invalid_request");
        requireText(request.redirectUri(), "redirect_uri", "invalid_request");
        requireText(request.codeVerifier(), "code_verifier", "invalid_request");

        OAuthClient client = oauthClientRepository
                .findById(request.clientId())
                .orElseThrow(() ->
                        new TokenExchangeException("invalid_client", "Invalid client")
                );

        if (!client.isEnabled()) {
            throw new TokenExchangeException(
                    "invalid_client",
                    "Client is disabled"
            );
        }

        Optional<PasslyAuthorizationCode> optionalCode =
                authorizationCodeRepository.consume(request.code());

        PasslyAuthorizationCode authorizationCode =
                optionalCode.orElseThrow(() ->
                        new TokenExchangeException(
                                "invalid_grant",
                                "Invalid or expired authorization code"
                        )
                );

        if (authorizationCode.isExpired()) {
            throw new TokenExchangeException(
                    "invalid_grant",
                    "Invalid or expired authorization code"
            );
        }

        if (!client.getClientId()
                .equals(authorizationCode.clientId())) {

            throw new TokenExchangeException(
                    "invalid_grant",
                    "Authorization code does not belong to client"
            );
        }

        if (!request.redirectUri()
                .equals(authorizationCode.redirectUri())) {

            throw new TokenExchangeException(
                    "invalid_grant",
                    "redirect_uri does not match authorization request"
            );
        }

        verifyPkce(
                request.codeVerifier(),
                authorizationCode.codeChallenge(),
                authorizationCode.codeChallengeMethod()
        );

        User user = userRepository
                .findById(authorizationCode.userId())
                .orElseThrow(() ->
                        new TokenExchangeException(
                                "invalid_grant",
                                "User associated with authorization code not found"
                        )
                );

        String accessToken =
                jwtTokenService.createAccessToken(user, client);

        String refreshToken =
                refreshTokenService.create(user, client);

        return new TokenResponse(
                accessToken,
                "Bearer",
                900,
                refreshToken
        );
    }

    private TokenResponse exchangeRefreshToken(
            TokenRequest request
    ) {

        requireText(request.refreshToken(), "refresh_token", "invalid_request");
        requireText(request.clientId(), "client_id", "invalid_request");

        OAuthClient client = oauthClientRepository
                .findById(request.clientId())
                .orElseThrow(() ->
                        new TokenExchangeException("invalid_client", "Invalid client")
                );

        if (!client.isEnabled()) {
            throw new TokenExchangeException(
                    "invalid_client",
                    "Client is disabled"
            );
        }

        RotatedRefreshToken rotated =
                refreshTokenService.rotate(
                        request.refreshToken(),
                        client
                );

        String accessToken =
                jwtTokenService.createAccessToken(
                        rotated.user(),
                        client
                );

        return new TokenResponse(
                accessToken,
                "Bearer",
                900,
                rotated.plaintextToken()
        );
    }

    private void verifyPkce(
            String codeVerifier,
            String codeChallenge,
            String codeChallengeMethod
    ) {

        // Validate code_verifier formatting per RFC 7636 §4.1
        validateCodeVerifier(codeVerifier);

        if (!"S256".equals(codeChallengeMethod)) {
            throw new TokenExchangeException(
                    "invalid_request",
                    "Unsupported code_challenge_method"
            );
        }

        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash =
                    digest.digest(
                            codeVerifier.getBytes(
                                    java.nio.charset.StandardCharsets.US_ASCII
                            )
                    );

            String calculatedChallenge =
                    Base64.getUrlEncoder()
                            .withoutPadding()
                            .encodeToString(hash);

            boolean valid =
                    MessageDigest.isEqual(
                            calculatedChallenge.getBytes(
                                    java.nio.charset.StandardCharsets.US_ASCII
                            ),
                            codeChallenge.getBytes(
                                    java.nio.charset.StandardCharsets.US_ASCII
                            )
                    );

            if (!valid) {
                throw new TokenExchangeException(
                        "invalid_grant",
                        "Invalid code_verifier"
                );
            }

        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "SHA-256 algorithm is unavailable",
                    e
            );
        }
    }

    private void validateCodeVerifier(String codeVerifier) {
        if (codeVerifier == null || codeVerifier.isBlank()) {
            throw new TokenExchangeException("invalid_request", "code_verifier is required");
        }
        int len = codeVerifier.length();
        if (len < 43 || len > 128) {
            throw new TokenExchangeException("invalid_grant", "Invalid code_verifier length");
        }
        for (int i = 0; i < len; i++) {
            char c = codeVerifier.charAt(i);
            if (!isCodeVerifierChar(c)) {
                throw new TokenExchangeException("invalid_grant", "Invalid characters in code_verifier");
            }
        }
    }

    private boolean isCodeVerifierChar(char c) {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' || c == '.' || c == '_' || c == '~';
    }

    private void requireText(
            String value,
            String field,
            String errorCode
    ) {

        if (value == null || value.isBlank()) {
            throw new TokenExchangeException(
                    errorCode,
                    field + " is required"
            );
        }
    }
}
