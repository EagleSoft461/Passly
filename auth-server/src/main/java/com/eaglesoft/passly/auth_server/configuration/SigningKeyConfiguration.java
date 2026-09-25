package com.eaglesoft.passly.auth_server.configuration;

import com.eaglesoft.passly.auth_server.authorization.security.FileSystemSigningKeyStore;
import com.eaglesoft.passly.auth_server.authorization.security.SigningKeyStore;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;

@Configuration
public class SigningKeyConfiguration {

    @Bean
    public SigningKeyStore signingKeyStore(
            @Value("${passly.security.signing-key.directory}")
            String keyDirectory
    ) {
        return new FileSystemSigningKeyStore(
                Path.of(keyDirectory)
        );
    }
}
