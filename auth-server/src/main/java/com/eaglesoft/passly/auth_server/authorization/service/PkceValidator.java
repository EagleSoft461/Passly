package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.InvalidPkceException;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Validates the PKCE parameters of an /oauth2/authorize request. This is
 * NOT the cryptographic code_verifier check — that happens later, at
 * /oauth2/token, against the code_challenge this class accepts here.
 *
 * Per ADR-001 Decision 1: PKCE is mandatory for every client, and S256
 * is the only supported code_challenge_method — "plain" is intentionally
 * not accepted, even though the RFC allows it.
 */
@Component
public class PkceValidator {

    private static final String SUPPORTED_METHOD = "S256";

    public void validate(String codeChallenge, String codeChallengeMethod) {
        if (!StringUtils.hasText(codeChallenge)) {
            throw new InvalidPkceException("code_challenge is required");
        }
        if (!StringUtils.hasText(codeChallengeMethod)) {
            throw new InvalidPkceException("code_challenge_method is required");
        }
        if (!SUPPORTED_METHOD.equals(codeChallengeMethod)) {
            throw new InvalidPkceException(
                    "Unsupported code_challenge_method: " + codeChallengeMethod
                            + " — only " + SUPPORTED_METHOD + " is supported");
        }

        // RFC 7636 §4.2: code_challenge is BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
        // SHA-256 is 32 bytes. Unpadded Base64URL encoding is always exactly 43 characters.
        if (codeChallenge.length() != 43) {
            throw new InvalidPkceException("Invalid code_challenge format");
        }
        for (int i = 0; i < 43; i++) {
            char c = codeChallenge.charAt(i);
            if (!isBase64UrlChar(c)) {
                throw new InvalidPkceException("Invalid code_challenge format");
            }
        }
    }

    private boolean isBase64UrlChar(char c) {
        return (c >= 'A' && c <= 'Z') ||
               (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') ||
               c == '-' || c == '_';
    }
}
