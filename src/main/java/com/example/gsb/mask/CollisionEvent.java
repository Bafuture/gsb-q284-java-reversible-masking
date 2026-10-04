package com.example.gsb.mask;

import java.time.Instant;

/** 一次碰撞事件：token 同时被 firstValue 与 incomingValue 命中。 */
public record CollisionEvent(String field, String token, String firstValue,
                             String incomingValue, String keyVersionId, Instant at) {
}
