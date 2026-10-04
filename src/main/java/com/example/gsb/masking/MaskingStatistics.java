package com.example.gsb.masking;

/**
 * Point-in-time snapshot of the service counters.
 *
 * @param mappedCount      total number of mask operations performed
 * @param revealCount      total number of successful authorized reveals
 * @param keyVersionCount  number of key versions held by the key store
 * @param collisionCount   number of collisions detected so far
 */
public record MaskingStatistics(long mappedCount, long revealCount,
                                int keyVersionCount, long collisionCount) {
}
