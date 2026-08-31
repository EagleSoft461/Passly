package com.eaglesoft.passly.auth_server.authorization.model;

import com.eaglesoft.passly.auth_server.domain.User;

public record RotatedRefreshToken(
        String plaintextToken,
        User user
) {
    public RotatedRefreshToken {
        if (plaintextToken == null || plaintextToken.isBlank()) {
            throw new IllegalArgumentException(
                    "plaintextToken cannot be null or blank"
            );
        }

        if (user == null) {
            throw new IllegalArgumentException(
                    "user cannot be null"
            );
        }
    }
}
