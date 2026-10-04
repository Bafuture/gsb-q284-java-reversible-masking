package com.example.gsb.masking;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Base64;

/**
 * Default {@link TokenCipher} built only on JDK crypto primitives.
 *
 * <ul>
 *   <li>{@link FieldFormat#FORMAT_PRESERVING}: an HMAC-SHA-256 derived
 *   keystream shifts every character inside its own alphabet
 *   (digits, lower, upper), preserving length and character classes.
 *   The shift is a bijection per position, so the transform is
 *   exactly reversible.</li>
 *   <li>{@link FieldFormat#GENERIC}: AES-GCM with an SIV-style nonce
 *   (HMAC of the plaintext) prepended to the ciphertext, making the
 *   output deterministic while keeping the token decryptable.</li>
 * </ul>
 */
public class DefaultTokenCipher implements TokenCipher {

    private static final String DIGITS = "0123456789";
    private static final String LOWER = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;

    @Override
    public String encrypt(byte[] key, String field, FieldFormat format, String value) {
        return switch (format) {
            case FORMAT_PRESERVING -> fpe(key, field, value, true);
            case GENERIC -> aesGcm(key, field, value, true);
        };
    }

    @Override
    public String decrypt(byte[] key, String field, FieldFormat format, String token) {
        return switch (format) {
            case FORMAT_PRESERVING -> fpe(key, field, token, false);
            case GENERIC -> aesGcm(key, field, token, false);
        };
    }

    // ---- format-preserving transform -------------------------------------

    private static String fpe(byte[] key, String field, String input, boolean encrypt) {
        byte[] stream = keystream(key, field, input.length());
        StringBuilder out = new StringBuilder(input.length());
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            String alphabet = alphabetOf(c);
            if (alphabet == null) {
                out.append(c);
                continue;
            }
            int n = alphabet.length();
            int shift = stream[i] & 0xFF;
            int idx = alphabet.indexOf(c);
            int mapped = encrypt
                    ? Math.floorMod(idx + shift, n)
                    : Math.floorMod(idx - shift, n);
            out.append(alphabet.charAt(mapped));
        }
        return out.toString();
    }

    private static String alphabetOf(char c) {
        if (c >= '0' && c <= '9') {
            return DIGITS;
        }
        if (c >= 'a' && c <= 'z') {
            return LOWER;
        }
        if (c >= 'A' && c <= 'Z') {
            return UPPER;
        }
        return null;
    }

    /** Deterministic keystream bound to (key, field, length). */
    private static byte[] keystream(byte[] key, String field, int length) {
        byte[] out = new byte[length];
        int produced = 0;
        int counter = 0;
        while (produced < length) {
            byte[] block = hmacSha256(key,
                    "fpe\0" + field + "\0" + length + "\0" + counter);
            int take = Math.min(block.length, length - produced);
            System.arraycopy(block, 0, out, produced, take);
            produced += take;
            counter++;
        }
        return out;
    }

    // ---- opaque deterministic token ---------------------------------------

    private static String aesGcm(byte[] key, String field, String input, boolean encrypt) {
        try {
            if (encrypt) {
                byte[] iv = Arrays.copyOf(
                        hmacSha256(key, "iv\0" + field + "\0" + input), GCM_IV_BYTES);
                byte[] ct = gcm(key, iv, Cipher.ENCRYPT_MODE,
                        input.getBytes(StandardCharsets.UTF_8));
                byte[] token = new byte[iv.length + ct.length];
                System.arraycopy(iv, 0, token, 0, iv.length);
                System.arraycopy(ct, 0, token, iv.length, ct.length);
                return Base64.getUrlEncoder().withoutPadding().encodeToString(token);
            }
            byte[] token = Base64.getUrlDecoder().decode(input);
            if (token.length <= GCM_IV_BYTES) {
                throw new IllegalArgumentException("token too short to contain IV and ciphertext");
            }
            byte[] iv = Arrays.copyOf(token, GCM_IV_BYTES);
            byte[] ct = Arrays.copyOfRange(token, GCM_IV_BYTES, token.length);
            return new String(gcm(key, iv, Cipher.DECRYPT_MODE, ct), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("token cipher failure: " + e.getMessage(), e);
        }
    }

    private static byte[] gcm(byte[] key, byte[] iv, int mode, byte[] data)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(mode, new SecretKeySpec(normalizeAesKey(key), "AES"),
                new GCMParameterSpec(GCM_TAG_BITS, iv));
        return cipher.doFinal(data);
    }

    /** Derives a 128-bit AES key from the (arbitrary length) masking key. */
    private static byte[] normalizeAesKey(byte[] key) {
        return Arrays.copyOf(hmacSha256(key, "aes-key"), 16);
    }

    private static byte[] hmacSha256(byte[] key, String message) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }
}
