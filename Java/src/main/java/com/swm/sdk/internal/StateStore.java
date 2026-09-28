package com.swm.sdk.internal;

import com.swm.sdk.SwmException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Optional;

public final class StateStore {
    private final Path directory;
    private final byte[] entropy;

    public StateStore(String appId, Path overrideDirectory) {
        if (appId == null || appId.isBlank()) {
            throw new SwmException.Configuration("appId is required");
        }
        var appHash = CryptoUtil.hex(CryptoUtil.sha256(appId.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
        this.directory = overrideDirectory != null
            ? overrideDirectory.toAbsolutePath()
            : Path.of(NativeWindows.localAppData().value, "SwmSdk", appHash.substring(0, 12));
        this.entropy = CryptoUtil.sha256(
            ("SwmSdkStateV2\n" + appId).getBytes(java.nio.charset.StandardCharsets.UTF_8));
        try {
            Files.createDirectories(directory);
        } catch (IOException exception) {
            throw new SwmException.Identity("cannot create SDK state directory", exception);
        }
    }

    public Path directory() {
        return directory;
    }

    public Path path(String name) {
        return directory.resolve(name);
    }

    public Optional<byte[]> readProtected(String name) {
        var path = path(name);
        if (!Files.isRegularFile(path)) {
            return Optional.empty();
        }
        try {
            var ciphertext = Files.readAllBytes(path);
            if (ciphertext.length == 0 || ciphertext.length > 1024 * 1024) {
                return Optional.empty();
            }
            return Optional.of(NativeWindows.unprotect(ciphertext, entropy));
        } catch (IOException | RuntimeException exception) {
            return Optional.empty();
        }
    }

    public void writeProtected(String name, byte[] plaintext) {
        var temporary = path(name + ".tmp");
        var target = path(name);
        try {
            var ciphertext = NativeWindows.protect(plaintext, entropy);
            Files.write(temporary, ciphertext, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            try {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING,
                    StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException atomicFailure) {
                Files.move(temporary, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException exception) {
            try {
                Files.deleteIfExists(temporary);
            } catch (IOException ignored) {
                // Best effort cleanup.
            }
            throw new SwmException.Identity("cannot write SDK state", exception);
        }
    }

    public void erase(String name) {
        try {
            Files.deleteIfExists(path(name));
        } catch (IOException ignored) {
            // The next read treats an unreadable state file as absent.
        }
    }
}
