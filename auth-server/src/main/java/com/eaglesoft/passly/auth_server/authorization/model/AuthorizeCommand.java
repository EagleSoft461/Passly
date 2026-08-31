package com.eaglesoft.passly.auth_server.authorization.model;

/**
 * Input to AuthorizationService.authorize(), assembled by the controller
 * from the /oauth2/authorize query parameters. Keeps the service layer
 * free of any HTTP/servlet types.
 */
public record AuthorizeCommand(
        String clientId,
        String responseType,
        String redirectUri,
        String state,
        String codeChallenge,
        String codeChallengeMethod,
        String provider
) {
}
