package com.example.gsb.mask;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;

/** 一个版本的密钥材料。 */
public record KeyVersion(String id, byte[] secret) {

    public KeyVersion {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(secret, "secret");
        if (id.isBlank()) {
            throw new IllegalArgumentException("密钥版本 id 不能为空");
        }
        if (secret.length < 16) {
            throw new IllegalArgumentException("密钥长度至少 16 字节");
        }
        secret = Arrays.copyOf(secret, secret.length);
    }

    public static KeyVersion of(String id, String secret) {
        return new KeyVersion(id, secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public byte[] secret() {
        return Arrays.copyOf(secret, secret.length);
    }
}
