package com.example.gsb.masking;

/**
 * Thrown when a token references a key version that is no longer held
 * in the key store, so its original value cannot be recovered.
 */
public class UnknownKeyVersionException extends RuntimeException {

    public UnknownKeyVersionException(String message) {
        super(message);
    }
}
