package com.example.gsb.mask;

import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicLong;

/** 运行统计：映射条数、还原次数、密钥版本数、碰撞数及碰撞明细。 */
public final class MaskingStats {

    private static final int MAX_KEPT_COLLISIONS = 1000;

    private final Keyring keyring;
    private final MappingVault vault;
    private final AtomicLong unmaskCount = new AtomicLong();
    private final AtomicLong collisionCount = new AtomicLong();
    private final ConcurrentLinkedQueue<CollisionEvent> collisions = new ConcurrentLinkedQueue<>();

    MaskingStats(Keyring keyring, MappingVault vault) {
        this.keyring = keyring;
        this.vault = vault;
    }

    /** 当前映射库中的映射条数。 */
    public long mappingCount() {
        return vault.mappingCount();
    }

    /** 成功还原次数。 */
    public long unmaskCount() {
        return unmaskCount.get();
    }

    /** 密钥环中的密钥版本数。 */
    public int keyVersionCount() {
        return keyring.size();
    }

    /** 检测到的碰撞总数。 */
    public long collisionCount() {
        return collisionCount.get();
    }

    /** 碰撞明细（最多保留最近 1000 条）。 */
    public List<CollisionEvent> collisionEvents() {
        return List.copyOf(collisions);
    }

    void recordUnmask() {
        unmaskCount.incrementAndGet();
    }

    void recordCollision(CollisionEvent event) {
        collisionCount.incrementAndGet();
        if (collisions.size() < MAX_KEPT_COLLISIONS) {
            collisions.add(event);
        }
    }
}
