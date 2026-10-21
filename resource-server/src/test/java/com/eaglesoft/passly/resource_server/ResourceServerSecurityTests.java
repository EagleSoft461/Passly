package com.eaglesoft.passly.resource_server;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class ResourceServerSecurityTests {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void shouldReturn401WhenTokenIsMissing() throws Exception {
        mockMvc.perform(get("/api/userinfo"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldReturn200WhenProfileScopeIsPresent() throws Exception {
        mockMvc.perform(
                get("/api/userinfo")
                        .with(jwt().authorities(
                                new SimpleGrantedAuthority("SCOPE_profile")
                        ))
        ).andExpect(status().isOk());
    }

    @Test
    void shouldReturn403WhenProfileScopeIsMissing() throws Exception {
        mockMvc.perform(
                get("/api/userinfo")
                        .with(jwt().authorities(
                                new SimpleGrantedAuthority("SCOPE_email")
                        ))
        ).andExpect(status().isForbidden());
    }

    @Test
    void shouldReturn401ForMeWhenTokenIsMissing() throws Exception {
        mockMvc.perform(get("/api/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void shouldReturnUserClaimsFromMeEndpoint() throws Exception {
        mockMvc.perform(
                get("/api/me")
                        .with(jwt()
                                .jwt(token -> token
                                        .subject("user-123")
                                        .issuer("https://passly.local")
                                        .claim("aud", java.util.List.of(
                                                "passly-demo-client"
                                        ))
                                )
                        )
        )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value("user-123"))
                .andExpect(jsonPath("$.issuer").value("https://passly.local"))
                .andExpect(jsonPath("$.audience[0]").value("passly-demo-client"));
    }
}