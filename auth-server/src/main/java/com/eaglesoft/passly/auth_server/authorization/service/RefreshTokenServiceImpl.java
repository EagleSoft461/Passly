package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.TokenExchangeException;
import com.eaglesoft.passly.auth_server.authorization.model.RotatedRefreshToken;
import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import com.eaglesoft.passly.auth_server.domain.RefreshToken;
import com.eaglesoft.passly.auth_server.domain.User;
import com.eaglesoft.passly.auth_server.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

@Service
public class RefreshTokenServiceImpl implements RefreshTokenService {

    private static final Duration REFRESH_TOKEN_TTL = Duration.ofDays(7);
    private static final int TOKEN_BYTES = 32;

    private final RefreshTokenRepository refreshTokenRepository;
    private final SecureRandom secureRandom;

    public RefreshTokenServiceImpl(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.secureRandom = new SecureRandom();
    }

    @Override
    @Transactional
    public String create(User user, OAuthClient client) {

        String plaintextToken = generateToken();
        String tokenHash = hashToken(plaintextToken);

        UUID tokenFamilyId = UUID.randomUUID();

        RefreshToken refreshToken = new RefreshToken(
                user,
                client,
                tokenHash,
                tokenFamilyId,
                Instant.now().plus(REFRESH_TOKEN_TTL)
        );

        refreshTokenRepository.save(refreshToken);

        return plaintextToken;
    }

    @Override
    @Transactional
    public RotatedRefreshToken rotate(
            String plaintextToken,
            OAuthClient client
    ) {

        String tokenHash = hashToken(plaintextToken);

        RefreshToken existing = refreshTokenRepository
                .findByTokenHash(tokenHash)
                .orElseThrow(() ->
                        new TokenExchangeException(
                                "Invalid refresh token"
                        )
                );

        /*
         * Reuse of a revoked token is treated as a
         * possible token theft signal.
         */
        if (existing.isRevoked()) {
            revokeFamily(existing);

            throw new TokenExchangeException(
                    "Refresh token reuse detected"
            );
        }

        if (existing.isExpired()) {
            existing.revoke();
            refreshTokenRepository.save(existing);

            throw new TokenExchangeException(
                    "Refresh token expired"
            );
        }

        /*
         * The refresh token must belong to the
         * requesting OAuth client.
         */
        if (!existing.getClient().getClientId()
                .equals(client.getClientId())) {

            throw new TokenExchangeException(
                    "Refresh token does not belong to client"
            );
        }

        String replacementPlaintext = generateToken();
        String replacementHash = hashToken(
                replacementPlaintext
        );

        RefreshToken replacement = new RefreshToken(
                existing.getUser(),
                existing.getClient(),
                replacementHash,
                existing.getTokenFamilyId(),
                Instant.now().plus(REFRESH_TOKEN_TTL)
        );

        replacement =
                refreshTokenRepository.save(replacement);

        /*
         * Revoke the old token and link it to
         * the replacement.
         */
        existing.markReplacedBy(
                replacement.getId()
        );

        refreshTokenRepository.save(existing);

        return new RotatedRefreshToken(
                replacementPlaintext,
                existing.getUser()
        );
    }

    @Override
    @Transactional
    public void revoke(String plaintextToken) {

        String tokenHash = hashToken(plaintextToken);

        refreshTokenRepository
                .findByTokenHash(tokenHash)
                .ifPresent(token -> {
                    token.revoke();
                    refreshTokenRepository.save(token);
                });
    }

    @Override
    @Transactional
    public void revokeFamily(RefreshToken token) {

        List<RefreshToken> familyTokens =
                refreshTokenRepository
                        .findAllByTokenFamilyIdAndRevokedAtIsNull(
                                token.getTokenFamilyId()
                        );

        for (RefreshToken familyToken : familyTokens) {
            familyToken.revoke();
        }

        refreshTokenRepository.saveAll(familyTokens);
    }

    private String generateToken() {

        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    private String hashToken(String token) {

        try {
            MessageDigest digest =
                    MessageDigest.getInstance("SHA-256");

            byte[] hash =
                    digest.digest(
                            token.getBytes(StandardCharsets.UTF_8)
                    );

            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(hash);

        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(
                    "SHA-256 algorithm is unavailable", e);
        }
    }
}
