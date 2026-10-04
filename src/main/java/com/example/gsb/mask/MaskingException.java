package com.example.gsb.mask;

/** 脱敏/还原失败的统一异常，携带可读原因。 */
public class MaskingException extends RuntimeException {

    private final RejectionReason reason;

    public MaskingException(RejectionReason reason, String detail) {
        super(reason.message() + ": " + detail);
        this.reason = reason;
    }

    public MaskingException(RejectionReason reason, String detail, Throwable cause) {
        super(reason.message() + ": " + detail, cause);
        this.reason = reason;
    }

    public RejectionReason reason() {
        return reason;
    }
}
