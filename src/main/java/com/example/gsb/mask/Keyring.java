package com.example.gsb.mask;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 版本化密钥环：最新版本用于新数据脱敏，历史版本保留用于老数据还原。
 * 线程安全。
 */
public final class Keyring {

    private final Map<String, KeyVersion> versions = new LinkedHashMap<>();
    private String currentId;

    public Keyring(KeyVersion initial) {
        add(initial);
    }

    public static Keyring of(String id, String secret) {
        return new Keyring(KeyVersion.of(id, secret));
    }

    /** 轮换：加入新版本并设为当前版本。 */
    public synchronized void rotate(KeyVersion version) {
        add(version);
    }

    private void add(KeyVersion version) {
        if (versions.containsKey(version.id())) {
            throw new IllegalArgumentException("密钥版本已存在: " + version.id());
        }
        versions.put(version.id(), version);
        currentId = version.id();
    }

    public synchronized KeyVersion current() {
        return versions.get(currentId);
    }

    public synchronized Optional<KeyVersion> find(String id) {
        return Optional.ofNullable(versions.get(id));
    }

    public synchronized int size() {
        return versions.size();
    }

    public synchronized List<String> ids() {
        return List.copyOf(new ArrayList<>(versions.keySet()));
    }
}
