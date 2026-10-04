package com.example.gsb.masking;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Reversible masking and authorized reveal service.
 *
 * <p>Masking is deterministic: for the same field, value and key version the
 * same token is produced, even from separate datasets or service instances
 * configured with the same key. Tokens carry their key version, so after
 * rotation old data still reveals with the retained historical key while new
 * data is masked with the current key.</p>
 *
 * <p>Every token produced for a field/key-version is registered. A new
 * original value colliding with an existing one on the same token is
 * reported as a {@link Collision}.</p>
 */
public class MaskingService {

    private final KeyStore keyStore;
    private final TokenCipher cipher;
    private final AuthorizationPolicy authorizationPolicy;

    /** registryKey (field \0 version \0 token) -> original value */
    private final Map<String, String> tokenRegistry = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Collision> collisions = new CopyOnWriteArrayList<>();
    private final AtomicLong mappedCount = new AtomicLong();
    private final AtomicLong revealCount = new AtomicLong();

    public MaskingService(byte[] initialKey, AuthorizationPolicy authorizationPolicy) {
        this(new KeyStore(initialKey), new DefaultTokenCipher(), authorizationPolicy);
    }

    public MaskingService(KeyStore keyStore, TokenCipher cipher,
                          AuthorizationPolicy authorizationPolicy) {
        this.keyStore = Objects.requireNonNull(keyStore, "keyStore");
        this.cipher = Objects.requireNonNull(cipher, "cipher");
        this.authorizationPolicy = Objects.requireNonNull(authorizationPolicy, "authorizationPolicy");
    }

    /**
     * Masks a value with format-preserving mapping (suitable for phone
     * numbers, national ids and other structured values).
     */
    public MaskedValue mask(String field, String value) {
        return mask(field, value, FieldFormat.FORMAT_PRESERVING);
    }

    public MaskedValue mask(String field, String value, FieldFormat format) {
        Objects.requireNonNull(field, "field");
        Objects.requireNonNull(value, "value");
        Objects.requireNonNull(format, "format");
        int version = keyStore.currentVersion();
        String token = cipher.encrypt(keyStore.currentKey(), field, format, value);

        String registryKey = registryKey(field, version, token);
        tokenRegistry.compute(registryKey, (key, existing) -> {
            if (existing != null && !existing.equals(value)) {
                collisions.add(new Collision(field, version, token, existing, value));
            }
            return existing == null ? value : existing;
        });
        mappedCount.incrementAndGet();
        return new MaskedValue(field, version, format, token);
    }

    /**
     * Reveals an original value. Requires an authorization accepted by the
     * configured policy; otherwise throws {@link UnauthorizedRevealException}
     * with an explanatory reason.
     */
    public String reveal(MaskedValue masked, Authorization authorization) {
        Objects.requireNonNull(masked, "masked");
        Objects.requireNonNull(authorization, "authorization");
        String grantee = authorization.grantee();
        if (!authorizationPolicy.isAuthorized(grantee, masked.field())) {
            throw new UnauthorizedRevealException(
                    "reveal denied: grantee '" + grantee
                            + "' is not authorized for field '" + masked.field()
                            + "' (keyVersion=" + masked.keyVersion() + ")");
        }
        byte[] key = keyStore.keyFor(masked.keyVersion());
        String value = cipher.decrypt(key, masked.field(), masked.format(), masked.token());
        revealCount.incrementAndGet();
        return value;
    }

    /** Rotates the active key. Historical versions stay available for reveal. */
    public int rotateKey(byte[] newKey) {
        return keyStore.rotate(newKey);
    }

    public MaskingStatistics statistics() {
        return new MaskingStatistics(
                mappedCount.get(),
                revealCount.get(),
                keyStore.versionCount(),
                collisions.size());
    }

    /** All collisions detected so far, in detection order. */
    public List<Collision> detectedCollisions() {
        return List.copyOf(collisions);
    }

    private static String registryKey(String field, int version, String token) {
        return field + '\0' + version + '\0' + token;
    }
}
