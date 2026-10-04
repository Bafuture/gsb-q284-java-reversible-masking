package com.example.gsb.mask;

import java.util.Objects;
import java.util.Set;

/**
 * 还原授权：字段级 + 密钥版本级。ALL_VERSIONS 表示允许还原任意历史版本的数据。
 */
public record Authorization(Set<String> fields, Set<String> keyVersionIds) {

    public static final Set<String> ALL_VERSIONS = Set.of("*");

    public Authorization {
        Objects.requireNonNull(fields, "fields");
        Objects.requireNonNull(keyVersionIds, "keyVersionIds");
        if (fields.isEmpty()) {
            throw new IllegalArgumentException("授权字段集合不能为空");
        }
        if (keyVersionIds.isEmpty()) {
            throw new IllegalArgumentException("授权密钥版本集合不能为空");
        }
        fields = Set.copyOf(fields);
        keyVersionIds = keyVersionIds.equals(ALL_VERSIONS) ? ALL_VERSIONS : Set.copyOf(keyVersionIds);
    }

    /** 授权指定字段的全部密钥版本。 */
    public static Authorization forFields(String... fields) {
        return new Authorization(Set.of(fields), ALL_VERSIONS);
    }

    /** 授权指定字段的指定密钥版本。 */
    public static Authorization forVersions(Set<String> fields, Set<String> keyVersionIds) {
        return new Authorization(fields, keyVersionIds);
    }

    public boolean allowsField(String field) {
        return fields.contains(field);
    }

    public boolean allowsVersion(String keyVersionId) {
        return keyVersionIds == ALL_VERSIONS || keyVersionIds.contains(keyVersionId);
    }
}
