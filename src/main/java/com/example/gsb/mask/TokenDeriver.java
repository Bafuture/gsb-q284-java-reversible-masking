package com.example.gsb.mask;

import java.security.GeneralSecurityException;

/**
 * 确定性令牌派生器：同一 (field, value, 密钥版本, attempt) 必须得到相同结果。
 * attempt 用于碰撞重试时改变输出。
 */
@FunctionalInterface
public interface TokenDeriver {

    byte[] derive(String field, String value, KeyVersion key, int attempt)
            throws GeneralSecurityException;
}
