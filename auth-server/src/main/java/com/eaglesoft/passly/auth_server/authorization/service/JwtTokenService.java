package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import com.eaglesoft.passly.auth_server.domain.User;

public interface JwtTokenService {

    /**
     * Creates a short-lived RS256 signed access token.
     *
     * @param user authenticated Passly user
     * @param client OAuth client receiving the token
     * @param scope validated scope string (space-delimited)
     * @return signed JWT access token
     */
    String createAccessToken(User user, OAuthClient client, String scope);
}
