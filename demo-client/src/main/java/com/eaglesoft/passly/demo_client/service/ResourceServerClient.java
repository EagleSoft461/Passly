package com.eaglesoft.passly.demo_client.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

@Service
public class ResourceServerClient {

    private final RestClient restClient;

    public ResourceServerClient(RestClient restClient) {
        this.restClient = restClient;
    }

    public String getUserInfo(String accessToken) {
        return restClient.get()
                .uri("http://localhost:8081/api/userinfo")
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .body(String.class);
    }
}
