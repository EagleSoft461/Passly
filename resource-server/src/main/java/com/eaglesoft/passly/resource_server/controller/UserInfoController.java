package com.eaglesoft.passly.resource_server.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserInfoController {

    @GetMapping("/userinfo")
    public String userInfo(Authentication authentication) {
        return "Authenticated user: " + authentication.getName();
    }

    @GetMapping("/me")
    public Map<String, Object> me(JwtAuthenticationToken authentication) {
        var jwt = authentication.getToken();

        return Map.of(
                "subject", jwt.getSubject(),
                "issuer", jwt.getIssuer().toString(),
                "audience", jwt.getAudience(),
                "scopes", authentication.getAuthorities().stream()
                        .map(authority -> authority.getAuthority())
                        .filter(authority -> authority.startsWith("SCOPE_"))
                        .map(authority -> authority.substring("SCOPE_".length()))
                        .toList()
        );
    }
}
