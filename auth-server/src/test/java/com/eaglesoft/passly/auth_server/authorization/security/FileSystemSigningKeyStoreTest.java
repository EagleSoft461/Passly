package com.eaglesoft.passly.auth_server.authorization.security;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

class FileSystemSigningKeyStoreTest {

    @TempDir
    Path tempDirectory;

    @Test
    void saveAndLoadShouldPreserveKeyPair() throws Exception {
        FileSystemSigningKeyStore store =
                new FileSystemSigningKeyStore(tempDirectory);

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);

        KeyPair originalKeyPair = generator.generateKeyPair();

        SigningIdentity original =
                new SigningIdentity(
                        originalKeyPair,
                        "test-key-id");

        store.save(original);

        SigningIdentity loaded = store.load();

        assertNotNull(loaded);

        assertEquals(
                original.getKeyId(),
                loaded.getKeyId());

        assertArrayEquals(
                original.getKeyPair()
                        .getPrivate()
                        .getEncoded(),
                loaded.getKeyPair()
                        .getPrivate()
                        .getEncoded());

        assertArrayEquals(
                original.getKeyPair()
                        .getPublic()
                        .getEncoded(),
                loaded.getKeyPair()
                        .getPublic()
                        .getEncoded());
    }

    @Test
    void loadShouldReturnNullWhenFilesDoNotExist() {
        FileSystemSigningKeyStore store =
                new FileSystemSigningKeyStore(tempDirectory);

        assertNull(store.load());
    }

    @Test
    void loadShouldFailWhenOnlyKeyFileExists() throws Exception {
        FileSystemSigningKeyStore store =
                new FileSystemSigningKeyStore(tempDirectory);

        Files.createDirectories(tempDirectory);

        Files.writeString(
                tempDirectory.resolve("signing_key.pem"),
                "invalid");

        assertThrows(
                IllegalStateException.class,
                store::load);
    }

    @Test
    void loadShouldFailWhenOnlyKeyIdFileExists() throws Exception {
        FileSystemSigningKeyStore store =
                new FileSystemSigningKeyStore(tempDirectory);

        Files.createDirectories(tempDirectory);

        Files.writeString(
                tempDirectory.resolve("key-id"),
                "test-key-id");

        assertThrows(
                IllegalStateException.class,
                store::load);
    }

    @Test
    void loadShouldFailForCorruptedKey() throws Exception {
        FileSystemSigningKeyStore store =
                new FileSystemSigningKeyStore(tempDirectory);

        Files.createDirectories(tempDirectory);

        Files.writeString(
                tempDirectory.resolve("signing_key.pem"),
                """
                -----BEGIN PRIVATE KEY-----
                corrupted-key
                -----END PRIVATE KEY-----
                """);

        Files.writeString(
                tempDirectory.resolve("key-id"),
                "test-key-id");

        assertThrows(
                IllegalStateException.class,
                store::load);
    }
}