package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.model.TokenRequest;
import com.eaglesoft.passly.auth_server.authorization.model.TokenResponse;

public interface TokenService {

    TokenResponse exchange(TokenRequest request);
}
