package com.example.gsb.masking;

/**
 * Declares how a field value should be tokenized.
 */
public enum FieldFormat {

    /**
     * Format-preserving mapping: length is kept and every character is
     * substituted within its own character class (digit -&gt; digit,
     * lowercase -&gt; lowercase, uppercase -&gt; uppercase). Characters
     * outside these classes (e.g. '-', 'X' separators) are left untouched.
     * Suitable for phone numbers, national ids and similar structured values.
     */
    FORMAT_PRESERVING,

    /**
     * Opaque mapping: the value is encrypted into a Base64URL token that
     * carries no visible structure. Suitable for free-form text.
     */
    GENERIC
}
