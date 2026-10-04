package com.example.gsb.masking;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Holds versioned masking keys. The current version is used for new masking
 * operations; historical versions are retained so data masked under older
 * keys can still be revealed after rotation.
 */
public class KeyStore {

    private final Map<Integer, byte[]> keysByVersion = new LinkedHashMap<>();
    private int currentVersion;

    public KeyStore(byte[] initialKey) {
        addKey(validateKey(initialKey));
    }

    /** Rotates to a new key and returns the new current version number. */
    public synchronized int rotate(byte[] newKey) {
        return addKey(validateKey(newKey));
    }

    private int addKey(byte[] key) {
        currentVersion++;
        keysByVersion.put(currentVersion, key);
        return currentVersion;
    }

    public synchronized int currentVersion() {
        return currentVersion;
    }

    public synchronized byte[] currentKey() {
        return keyFor(currentVersion);
    }

    public synchronized byte[] keyFor(int version) {
        byte[] key = keysByVersion.get(version);
        if (key == null) {
            throw new UnknownKeyVersionException(
                    "key version " + version + " is not held by this key store; "
                            + "available versions: " + keysByVersion.keySet());
        }
        return key.clone();
    }

    public synchronized int versionCount() {
        return keysByVersion.size();
    }

    public synchronized Map<Integer, byte[]> snapshot() {
        Map<Integer, byte[]> copy = new LinkedHashMap<>();
        keysByVersion.forEach((v, k) -> copy.put(v, k.clone()));
        return Collections.unmodifiableMap(copy);
    }

    private static byte[] validateKey(byte[] key) {
        Objects.requireNonNull(key, "key");
        if (key.length < 16) {
            throw new IllegalArgumentException("key must be at least 16 bytes");
        }
        return key.clone();
    }
}
