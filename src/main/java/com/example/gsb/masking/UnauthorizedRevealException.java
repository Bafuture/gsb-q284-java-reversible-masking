package com.example.gsb.masking;

/**
 * Thrown when a reveal request is made without valid authorization.
 * The message states the denied grantee and field so callers and auditors
 * understand the reason.
 */
public class UnauthorizedRevealException extends RuntimeException {

    public UnauthorizedRevealException(String message) {
        super(message);
    }
}
