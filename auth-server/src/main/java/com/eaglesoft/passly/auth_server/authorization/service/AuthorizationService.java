package com.eaglesoft.passly.auth_server.authorization.service;

import com.eaglesoft.passly.auth_server.authorization.model.AuthorizationResult;
import com.eaglesoft.passly.auth_server.authorization.model.AuthorizeCommand;

public interface AuthorizationService {

    AuthorizationResult authorize(AuthorizeCommand command);
}
