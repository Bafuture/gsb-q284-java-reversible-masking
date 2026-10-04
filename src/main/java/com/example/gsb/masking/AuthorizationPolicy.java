package com.example.gsb.masking;

import java.util.Set;

/**
 * Decides whether a grantee may reveal a given field.
 */
@FunctionalInterface
public interface AuthorizationPolicy {

    boolean isAuthorized(String grantee, String field);

    /** Policy that rejects every reveal request. */
    static AuthorizationPolicy denyAll() {
        return (grantee, field) -> false;
    }

    /** Policy that allows the given grantees to reveal every field. */
    static AuthorizationPolicy allow(Set<String> grantees) {
        Set<String> allowed = Set.copyOf(grantees);
        return (grantee, field) -> allowed.contains(grantee);
    }

    /** Policy that allows a specific grantee only on a specific field. */
    static AuthorizationPolicy fieldScoped(String grantee, String field) {
        return (g, f) -> g.equals(grantee) && f.equals(field);
    }
}
