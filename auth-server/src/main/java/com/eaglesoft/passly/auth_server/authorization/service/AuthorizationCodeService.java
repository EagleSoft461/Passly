package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.CodeIssuanceException;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationRequest;
import com.eaglesoft.passly.auth_server.authorization.model.PasslyAuthorizationCode;
import com.eaglesoft.passly.auth_server.authorization.repository.PasslyAuthorizationCodeRepository;
import com.eaglesoft.passly.auth_server.domain.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;

/**
 * Service responsible for issuing Passly authorization codes.
 * Codes are cryptographically secure, short-lived, and single-use.
 */
@Service
public class AuthorizationCodeService {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationCodeService.class);
    private static final Duration CODE_TTL = Duration.ofMinutes(2);
    private static final int CODE_BYTES = 32; // 256 bits

    private final PasslyAuthorizationCodeRepository codeRepository;
    private final SecureRandom secureRandom;

    public AuthorizationCodeService(PasslyAuthorizationCodeRepository codeRepository) {
        this.codeRepository = codeRepository;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Issues a Passly authorization code after successful external authentication.
     * The code contains all necessary information for later token exchange:
     * - User ID
     * - Client ID
     * - Validated redirect URI
     * - PKCE challenge for verification
     *
     * @param user The authenticated user
     * @param authorizationRequest The original authorization request (contains PKCE, client, redirect_uri)
     * @return The generated authorization code (plaintext, to be sent to client)
     * @throws CodeIssuanceException if code generation or storage fails
     */
    public String issueCode(User user, AuthorizationRequest authorizationRequest) {
        String code = generateCode();

        Instant now = Instant.now();
        PasslyAuthorizationCode authCode = new PasslyAuthorizationCode(
                code,
                user.getId(),
                authorizationRequest.clientId(),
                authorizationRequest.redirectUri(),
                authorizationRequest.codeChallenge(),
                authorizationRequest.codeChallengeMethod(),
                now,
                now.plus(CODE_TTL)
        );

        try {
            codeRepository.save(authCode);
            // Security: Log userId and clientId, but NEVER the code itself
            logger.info("Authorization code issued: userId={}, clientId={}",
                    user.getId(), authorizationRequest.clientId());
            return code;
        } catch (Exception ex) {
            // Security: Do NOT log the generated code
            throw new CodeIssuanceException("Failed to issue authorization code");
        }
    }

    /**
     * Generates a cryptographically secure random authorization code.
     * Uses SecureRandom with 32 bytes (256 bits) entropy.
     * Encoded as Base64URL for safe URL transmission.
     *
     * @return Base64URL-encoded authorization code (~43 characters)
     */
    private String generateCode() {
        byte[] bytes = new byte[CODE_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
