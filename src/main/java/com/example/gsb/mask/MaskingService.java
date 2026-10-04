package com.example.gsb.mask;

import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.HashSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * 可逆脱敏与映射还原服务。
 *
 * 脱敏：用确定性 HMAC 派生令牌，按字段格式保持规则生成输出，并在映射保险库中
 * 记录双向映射。同一 (字段, 原值, 密钥版本) 永远得到同一结果；跨数据集共用
 * 同一保险库时结果一致，可用于关联分析。
 *
 * 还原：必须持有字段级 + 密钥版本级授权，否则以明确原因拒绝。
 *
 * 密钥轮换：新数据用密钥环当前版本，历史版本保留后老数据仍可还原。
 */
public final class MaskingService {

    private static final int DEFAULT_MAX_RETRIES = 8;

    private final Keyring keyring;
    private final MappingVault vault;
    private final Map<String, FieldSpec> fields;
    private final TokenDeriver deriver;
    private final CollisionPolicy collisionPolicy;
    private final int maxRetries;
    private final MaskingStats stats;

    private MaskingService(Builder b) {
        this.keyring = b.keyring;
        this.vault = b.vault;
        this.fields = Map.copyOf(b.fields);
        this.deriver = b.deriver;
        this.collisionPolicy = b.collisionPolicy;
        this.maxRetries = b.maxRetries;
        this.stats = new MaskingStats(b.keyring, b.vault);
    }

    public static Builder builder() {
        return new Builder();
    }

    public MaskingStats stats() {
        return stats;
    }

    /** 对字段值脱敏。幂等：同一原值重复脱敏返回同一结果。 */
    public String mask(String field, String value) {
        Objects.requireNonNull(field, "field");
        Objects.requireNonNull(value, "value");
        FieldSpec spec = fields.get(field);
        if (spec == null) {
            throw new MaskingException(RejectionReason.UNKNOWN_FIELD, "字段: " + field);
        }
        KeyVersion current = keyring.current();
        int maxAttempt = collisionPolicy == CollisionPolicy.RETRY ? maxRetries : 0;
        Set<String> reportedCollisions = new HashSet<>();

        for (int attempt = 0; attempt <= maxAttempt; attempt++) {
            String token = materialize(spec, current, value, attempt);
            MappingVault.Outcome outcome = vault.intern(field, current.id(), value, token);
            switch (outcome.kind()) {
                case EXISTING -> {
                    return outcome.entry().token();
                }
                case CREATED -> {
                    return outcome.entry().token();
                }
                case COLLISION -> {
                    MappingVault.VaultEntry conflict = outcome.conflict();
                    String collisionKey = token + "" + conflict.original();
                    if (reportedCollisions.add(collisionKey)) {
                        stats.recordCollision(new CollisionEvent(field, token,
                                conflict.original(), value, current.id(), Instant.now()));
                    }
                    if (collisionPolicy == CollisionPolicy.REJECT) {
                        throw new MaskingException(RejectionReason.COLLISION_REJECTED,
                                "字段 " + field + " 原值 '" + value + "' 与 '"
                                        + conflict.original() + "' 映射为同一结果 '" + token + "'");
                    }
                }
            }
        }
        throw new MaskingException(RejectionReason.RETRY_EXHAUSTED,
                "字段 " + field + " 原值 '" + value + "' 重试 " + maxRetries + " 次仍发生碰撞");
    }

    /** 持授权还原；无授权时抛出 MaskingException 并说明原因。 */
    public String unmask(String field, String token, Authorization authorization) {
        Objects.requireNonNull(field, "field");
        Objects.requireNonNull(token, "token");
        Objects.requireNonNull(authorization, "authorization");
        if (fields.containsKey(field) && !authorization.allowsField(field)) {
            throw new MaskingException(RejectionReason.UNAUTHORIZED_FIELD, "字段: " + field);
        }
        MappingVault.VaultEntry entry = vault.lookupByToken(field, token)
                .orElseThrow(() -> new MaskingException(RejectionReason.UNKNOWN_TOKEN,
                        "字段 " + field + " 的映射值不存在"));
        if (!authorization.allowsField(entry.field())) {
            throw new MaskingException(RejectionReason.UNAUTHORIZED_FIELD, "字段: " + entry.field());
        }
        String versionId = entry.keyVersionId();
        keyring.find(versionId).orElseThrow(() -> new MaskingException(
                RejectionReason.KEY_VERSION_RETIRED, "密钥版本: " + versionId));
        if (!authorization.allowsVersion(versionId)) {
            throw new MaskingException(RejectionReason.UNAUTHORIZED_KEY_VERSION,
                    "密钥版本: " + versionId);
        }
        stats.recordUnmask();
        return entry.original();
    }

    private String materialize(FieldSpec spec, KeyVersion key, String value, int attempt) {
        try {
            byte[] stream = deriver.derive(spec.field(), value, key, attempt);
            return spec.format().materialize(stream, value);
        } catch (GeneralSecurityException e) {
            throw new MaskingException(RejectionReason.DERIVER_ERROR,
                    "字段 " + spec.field() + " 派生失败", e);
        }
    }

    public static final class Builder {
        private Keyring keyring;
        private MappingVault vault = new MappingVault();
        private final Map<String, FieldSpec> fields = new HashMap<>();
        private TokenDeriver deriver = new HmacTokenDeriver();
        private CollisionPolicy collisionPolicy = CollisionPolicy.REJECT;
        private int maxRetries = DEFAULT_MAX_RETRIES;

        public Builder keyring(Keyring keyring) {
            this.keyring = keyring;
            return this;
        }

        /** 多个数据集/服务实例共用同一保险库即可保证跨数据集映射一致。 */
        public Builder sharedVault(MappingVault vault) {
            this.vault = vault;
            return this;
        }

        public Builder field(FieldSpec spec) {
            this.fields.put(spec.field(), spec);
            return this;
        }

        public Builder deriver(TokenDeriver deriver) {
            this.deriver = deriver;
            return this;
        }

        public Builder collisionPolicy(CollisionPolicy policy) {
            this.collisionPolicy = policy;
            return this;
        }

        public Builder maxRetries(int maxRetries) {
            this.maxRetries = maxRetries;
            return this;
        }

        public MaskingService build() {
            if (keyring == null) {
                throw new IllegalStateException("必须提供 keyring");
            }
            if (fields.isEmpty()) {
                throw new IllegalStateException("至少注册一个字段");
            }
            return new MaskingService(this);
        }
    }
}
