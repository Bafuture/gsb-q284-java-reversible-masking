package com.example.gsb.mask;

/** 碰撞处理策略。 */
public enum CollisionPolicy {
    /** 检测到碰撞立即拒绝并报告。 */
    REJECT,
    /** 改变派生参数重试，直到结果唯一或重试耗尽。 */
    RETRY
}
