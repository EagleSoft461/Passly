package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.exception.ExternalIdentityRetrievalException;
import com.eaglesoft.passly.auth_server.authorization.model.ExternalUserInfo;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/**
 * Retrieves user information from Google's UserInfo endpoint.
 * Uses RestClient to call https://www.googleapis.com/oauth2/v3/userinfo
 * with Bearer token authentication.
 */
@Component
public class GoogleUserInfoRetriever implements ExternalIdentityRetriever {

    private static final String GOOGLE_USERINFO_ENDPOINT = "https://www.googleapis.com/oauth2/v3/userinfo";

    private final RestClient restClient;

    public GoogleUserInfoRetriever(RestClient.Builder restClientBuilder) {
        this.restClient = restClientBuilder.build();
    }

    @Override
    public String supports() {
        return "GOOGLE";
    }

    @Override
    public ExternalUserInfo retrieveUserInfo(String accessToken) {
        try {
            return restClient.get()
                    .uri(GOOGLE_USERINFO_ENDPOINT)
                    .header("Authorization", "Bearer " + accessToken)
                    .retrieve()
                    .body(ExternalUserInfo.class);
        } catch (Exception ex) {
            // Security: Do NOT include access token in exception message
            throw new ExternalIdentityRetrievalException(
                    "Failed to retrieve Google user info: " + ex.getMessage()
            );
        }
    }
}
