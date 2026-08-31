package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.model.RotatedRefreshToken;
import com.eaglesoft.passly.auth_server.domain.OAuthClient;
import com.eaglesoft.passly.auth_server.domain.RefreshToken;
import com.eaglesoft.passly.auth_server.domain.User;

public interface RefreshTokenService {

    String create(User user, OAuthClient client);

    RotatedRefreshToken rotate(
            String refreshToken,
            OAuthClient client
    );

    void revoke(String refreshToken);

    void revokeFamily(RefreshToken token);
}
