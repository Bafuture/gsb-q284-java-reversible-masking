package com.example.gsb.mask;

/** 操作被拒绝的原因，附带给调用方/审计的可读说明。 */
public enum RejectionReason {
    UNAUTHORIZED_FIELD("未授权访问该字段的还原能力"),
    UNAUTHORIZED_KEY_VERSION("授权范围不包含该映射值所用的密钥版本"),
    UNKNOWN_TOKEN("映射值不存在于映射库中（可能已脱库或被篡改）"),
    KEY_VERSION_RETIRED("映射所需的密钥版本已从密钥环中移除，无法验证授权"),
    COLLISION_REJECTED("不同原值映射到相同结果，按策略拒绝"),
    RETRY_EXHAUSTED("碰撞重试次数耗尽，仍无法生成唯一映射"),
    UNKNOWN_FIELD("字段未注册脱敏策略"),
    INVALID_FORMAT("原值不符合该字段的格式要求"),
    DERIVER_ERROR("令牌派生失败");

    private final String message;

    RejectionReason(String message) {
        this.message = message;
    }

    public String message() {
        return message;
    }
}
