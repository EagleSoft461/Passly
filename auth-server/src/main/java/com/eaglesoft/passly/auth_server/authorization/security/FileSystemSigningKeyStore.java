package com.eaglesoft.passly.auth_server.authorization.security;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

public class FileSystemSigningKeyStore implements SigningKeyStore {

    private final Path keyDirectory;

    public FileSystemSigningKeyStore(Path keyDirectory) {
        this.keyDirectory = keyDirectory;
    }

    @Override
    public SigningIdentity load() {
        Path keyFile = keyDirectory.resolve("signing_key.pem");
        Path keyIdFile = keyDirectory.resolve("key-id");

        if (!Files.exists(keyFile) && !Files.exists(keyIdFile)) {
            return null;
        }

        if (!Files.exists(keyFile) || !Files.exists(keyIdFile)) {
            throw new IllegalStateException(
                    "Signing key persistence is incomplete");
        }

        try {
            String pem = Files.readString(keyFile);
            String keyId = Files.readString(keyIdFile).trim();

            String base64Key = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] decodedKey = Base64.getDecoder().decode(base64Key);

            PKCS8EncodedKeySpec keySpec =
                    new PKCS8EncodedKeySpec(decodedKey);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            PrivateKey privateKey =
                    keyFactory.generatePrivate(keySpec);

            if (!(privateKey instanceof RSAPrivateCrtKey rsaPrivateKey)) {
                throw new IllegalStateException(
                        "Persisted private key is not an RSA CRT private key");
            }

            RSAPublicKeySpec publicKeySpec =
                    new RSAPublicKeySpec(
                            rsaPrivateKey.getModulus(),
                            rsaPrivateKey.getPublicExponent());

            PublicKey publicKey =
                    keyFactory.generatePublic(publicKeySpec);

            KeyPair keyPair = new KeyPair(publicKey, privateKey);

            return new SigningIdentity(keyPair, keyId);

        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to read persisted signing key", e);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to reconstruct persisted signing identity", e);
        }
    }

    @Override
    public void save(SigningIdentity identity) {
        PrivateKey privateKey = identity.getKeyPair().getPrivate();

        byte[] encodedKey = privateKey.getEncoded();

        String base64Key =
                Base64.getEncoder().encodeToString(encodedKey);

        String pem =
                "-----BEGIN PRIVATE KEY-----\n"
                        + base64Key
                        + "\n-----END PRIVATE KEY-----\n";

        String keyId = identity.getKeyId();

        try {
            Files.createDirectories(keyDirectory);

            Path keyFile =
                    keyDirectory.resolve("signing_key.pem");

            Files.writeString(keyFile, pem);

            Path keyIdFile =
                    keyDirectory.resolve("key-id");

            Files.writeString(keyIdFile, keyId);

        } catch (IOException e) {
            throw new IllegalStateException(
                    "Failed to persist signing key", e);
        }
    }
}
