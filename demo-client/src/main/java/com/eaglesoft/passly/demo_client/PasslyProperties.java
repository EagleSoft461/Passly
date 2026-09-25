package com.eaglesoft.passly.demo_client;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "passly")
public record PasslyProperties(
        String authorizationUri,
        String tokenUri,
        String jwkSetUri,
        String clientId,
        String redirectUri
) {
}
