package com.example.gsb.masking;

import java.util.Objects;

/**
 * The result of masking a single field value. Carries the key version that
 * produced the token so old data stays revealable after key rotation.
 */
public record MaskedValue(String field, int keyVersion, FieldFormat format, String token) {

    public MaskedValue {
        Objects.requireNonNull(field, "field");
        Objects.requireNonNull(format, "format");
        Objects.requireNonNull(token, "token");
        if (keyVersion < 1) {
            throw new IllegalArgumentException("keyVersion must be >= 1");
        }
    }

    @Override
    public String toString() {
        return field + "@v" + keyVersion + ":" + token;
    }
}
