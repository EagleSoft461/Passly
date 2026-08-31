package com.eaglesoft.passly.auth_server.configuration;

import com.eaglesoft.passly.auth_server.authorization.security.RsaKeyProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

@Configuration
public class JwtConfiguration {

    @Bean
    public RSAKey rsaKey(RsaKeyProvider keyProvider) {
        return new RSAKey.Builder(
                (java.security.interfaces.RSAPublicKey) keyProvider.getPublicKey()
        )
                .privateKey(
                        (java.security.interfaces.RSAPrivateKey) keyProvider.getPrivateKey()
                )
                .keyID(keyProvider.getKeyId())
                .build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {

        JWKSet jwkSet = new JWKSet(rsaKey);

        return (jwkSelector, securityContext) ->
                jwkSelector.select(jwkSet);
    }

    @Bean
    public JwtEncoder jwtEncoder(
            JWKSource<SecurityContext> jwkSource
    ) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public java.security.interfaces.RSAPrivateKey rsaPrivateKey(
            RsaKeyProvider keyProvider
    ) {
        return (java.security.interfaces.RSAPrivateKey)
                keyProvider.getPrivateKey();
    }

    @Bean
    public java.security.interfaces.RSAPublicKey rsaPublicKey(
            RsaKeyProvider keyProvider
    ) {
        return (java.security.interfaces.RSAPublicKey)
                keyProvider.getPublicKey();
    }
}
