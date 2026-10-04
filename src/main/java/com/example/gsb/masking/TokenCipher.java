package com.example.gsb.masking;

/**
 * Deterministic, reversible tokenization primitive. The same key, field and
 * value must always produce the same token, and the token must be
 * decryptable back to the value with the same key.
 */
public interface TokenCipher {

    String encrypt(byte[] key, String field, FieldFormat format, String value);

    String decrypt(byte[] key, String field, FieldFormat format, String token);
}
