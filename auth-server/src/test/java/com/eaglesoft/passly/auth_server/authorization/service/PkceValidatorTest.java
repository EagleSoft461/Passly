package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.exception.InvalidPkceException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class PkceValidatorTest {

    private final PkceValidator validator = new PkceValidator();

    @Test
    void shouldAcceptS256Challenge() {
        assertThatCode(() -> validator.validate("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "S256"))
                .doesNotThrowAnyException();
    }

    @Test
    void shouldRejectMissingChallenge() {
        assertThatThrownBy(() -> validator.validate(null, "S256"))
                .isInstanceOf(InvalidPkceException.class)
                .hasMessageContaining("code_challenge is required");
    }

    @Test
    void shouldRejectBlankChallenge() {
        assertThatThrownBy(() -> validator.validate("   ", "S256"))
                .isInstanceOf(InvalidPkceException.class)
                .hasMessageContaining("code_challenge is required");
    }

    @Test
    void shouldRejectMissingMethod() {
        assertThatThrownBy(() -> validator.validate("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", null))
                .isInstanceOf(InvalidPkceException.class)
                .hasMessageContaining("code_challenge_method is required");
    }

    @Test
    void shouldRejectPlainMethod() {
        assertThatThrownBy(() -> validator.validate("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "plain"))
                .isInstanceOf(InvalidPkceException.class)
                .hasMessageContaining("Unsupported code_challenge_method");
    }

    @Test
    void shouldRejectUnsupportedMethod() {
        assertThatThrownBy(() -> validator.validate("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", "md5"))
                .isInstanceOf(InvalidPkceException.class)
                .hasMessageContaining("Unsupported code_challenge_method");
    }

    @Test
    void shouldRejectShortChallenge() {
        assertThatThrownBy(() -> validator.validate("too-short", "S256"))
                .isInstanceOf(InvalidPkceException.class)
                .hasMessageContaining("Invalid code_challenge format");
    }

    @Test
    void shouldRejectChallengeWithInvalidCharacters() {
        assertThatThrownBy(() -> validator.validate("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjX+", "S256"))
                .isInstanceOf(InvalidPkceException.class)
                .hasMessageContaining("Invalid code_challenge format");
    }
}
