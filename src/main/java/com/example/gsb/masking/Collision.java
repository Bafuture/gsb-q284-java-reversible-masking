package com.example.gsb.masking;

/**
 * Records that two different original values produced the same token
 * for a field under the same key version.
 */
public record Collision(String field, int keyVersion, String token,
                        String existingValue, String newValue) {
}
