package com.eaglesoft.passly.auth_server.authorization.provider;

import com.eaglesoft.passly.auth_server.authorization.exception.TokenExchangeException;
import com.eaglesoft.passly.auth_server.authorization.model.ExternalTokenResponse;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

@Component
public class GoogleTokenExchanger implements IdentityProviderTokenExchanger {

    private static final String GOOGLE_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

    private final GoogleOAuthProperties properties;
    private final RestClient restClient;

    public GoogleTokenExchanger(GoogleOAuthProperties properties, RestClient.Builder restClientBuilder) {
        this.properties = properties;
        this.restClient = restClientBuilder.build();
    }

    @Override
    public String supports() {
        return "GOOGLE";
    }

    @Override
    public ExternalTokenResponse exchangeCode(String code) {
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("client_id", properties.clientId());
        body.add("client_secret", properties.clientSecret());
        body.add("code", code);
        body.add("grant_type", "authorization_code");
        body.add("redirect_uri", properties.redirectUri());

        try {
            return restClient.post()
                    .uri(GOOGLE_TOKEN_ENDPOINT)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(body)
                    .retrieve()
                    .body(ExternalTokenResponse.class);
        } catch (Exception ex) {
            throw new TokenExchangeException("Failed to exchange Google authorization code: " + ex.getMessage());
        }
    }
}
