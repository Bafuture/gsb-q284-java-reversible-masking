package com.example.gsb.mask;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * 映射保险库：保存 (字段, 密钥版本, 原值) -> 映射值 的正向映射与
 * (字段, 映射值) -> 原值 的反向映射，并负责碰撞检测。
 * 持有原值，属受信组件，不得出库。线程安全。
 */
public final class MappingVault {

    /** 一条映射记录。 */
    public record VaultEntry(String field, String keyVersionId, String original, String token) {
    }

    /** intern 结果：已存在 / 新建 / 碰撞。 */
    record Outcome(Kind kind, VaultEntry entry, VaultEntry conflict) {
        enum Kind {EXISTING, CREATED, COLLISION}
    }

    private final Map<String, VaultEntry> forward = new HashMap<>();
    private final Map<String, VaultEntry> reverse = new HashMap<>();

    private static String forwardKey(String field, String keyVersionId, String original) {
        return field + "" + keyVersionId + "" + original;
    }

    private static String reverseKey(String field, String token) {
        return field + "" + token;
    }

    /** 已存在则返回原记录；token 空闲则新建；token 被不同原值占用则报告碰撞。 */
    public synchronized Outcome intern(String field, String keyVersionId,
                                       String original, String token) {
        VaultEntry existing = forward.get(forwardKey(field, keyVersionId, original));
        if (existing != null) {
            return new Outcome(Outcome.Kind.EXISTING, existing, null);
        }
        VaultEntry conflict = reverse.get(reverseKey(field, token));
        if (conflict != null && !conflict.original().equals(original)) {
            return new Outcome(Outcome.Kind.COLLISION, null, conflict);
        }
        VaultEntry created = new VaultEntry(field, keyVersionId, original, token);
        forward.put(forwardKey(field, keyVersionId, original), created);
        reverse.put(reverseKey(field, token), created);
        return new Outcome(Outcome.Kind.CREATED, created, null);
    }

    /** 按 token 还原；跨版本命中多条时返回最新插入的一条。 */
    public synchronized Optional<VaultEntry> lookupByToken(String field, String token) {
        return Optional.ofNullable(reverse.get(reverseKey(field, token)));
    }

    public synchronized int mappingCount() {
        return forward.size();
    }

    public synchronized List<VaultEntry> entries() {
        return List.copyOf(new ArrayList<>(forward.values()));
    }
}
