package com.example.gsb.masking;

import java.util.Objects;

/**
 * Identity presented by a caller asking to reveal an original value.
 * Authorization is enforced by the {@link AuthorizationPolicy} the
 * {@link MaskingService} was configured with.
 */
public record Authorization(String grantee) {

    public Authorization {
        Objects.requireNonNull(grantee, "grantee");
        if (grantee.isBlank()) {
            throw new IllegalArgumentException("grantee must not be blank");
        }
    }
}
