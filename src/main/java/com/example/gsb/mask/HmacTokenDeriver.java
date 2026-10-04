package com.example.gsb.mask;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

/** 基于 HmacSHA256 的默认派生器，输出 32 字节。 */
public final class HmacTokenDeriver implements TokenDeriver {

    @Override
    public byte[] derive(String field, String value, KeyVersion key, int attempt)
            throws GeneralSecurityException {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key.secret(), "HmacSHA256"));
        mac.update(field.getBytes(StandardCharsets.UTF_8));
        mac.update((byte) 0);
        mac.update(value.getBytes(StandardCharsets.UTF_8));
        mac.update((byte) 0);
        mac.update(new byte[]{(byte) (attempt >>> 24), (byte) (attempt >>> 16),
                (byte) (attempt >>> 8), (byte) attempt});
        return mac.doFinal();
    }
}
