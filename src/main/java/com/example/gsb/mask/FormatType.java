package com.example.gsb.mask;

/**
 * 字段格式类型。materialize 把派生字节流加工成保持格式的字符串：
 * 长度与原值一致，且每个位置保持原有字符类型（数字->数字，字母->字母）。
 */
public enum FormatType {

    /** 手机号等纯数字：长度保持，逐位数字。 */
    PHONE {
        @Override
        public String materialize(byte[] stream, String original) {
            requireAllDigits(original, "手机号");
            StringBuilder out = new StringBuilder(original.length());
            for (int i = 0; i < original.length(); i++) {
                out.append((char) ('0' + digit(stream, i)));
            }
            return out.toString();
        }
    },

    /** 身份证：前 17 位保持数字，末位保持数字或 X/x。 */
    ID_CARD {
        @Override
        public String materialize(byte[] stream, String original) {
            if (original.length() != 18) {
                throw new MaskingException(RejectionReason.INVALID_FORMAT,
                        "身份证号长度必须为 18，实际为 " + original.length());
            }
            String body = original.substring(0, 17);
            requireAllDigits(body, "身份证号前 17 位");
            char last = original.charAt(17);
            StringBuilder out = new StringBuilder(18);
            for (int i = 0; i < 17; i++) {
                out.append((char) ('0' + digit(stream, i)));
            }
            if (Character.isDigit(last)) {
                out.append((char) ('0' + digit(stream, 17)));
            } else if (last == 'X' || last == 'x') {
                out.append('X');
            } else {
                throw new MaskingException(RejectionReason.INVALID_FORMAT,
                        "身份证号末位必须为数字或 X/x，实际为 " + last);
            }
            return out.toString();
        }
    },

    /** 无格式要求：输出 base64url 令牌（不保持长度）。 */
    GENERIC {
        @Override
        public String materialize(byte[] stream, String original) {
            return java.util.Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(java.util.Arrays.copyOf(stream, 18));
        }
    };

    public abstract String materialize(byte[] stream, String original);

    static int digit(byte[] stream, int index) {
        return (stream[index % stream.length] & 0xFF) % 10;
    }

    private static void requireAllDigits(String value, String label) {
        for (int i = 0; i < value.length(); i++) {
            if (!Character.isDigit(value.charAt(i))) {
                throw new MaskingException(RejectionReason.INVALID_FORMAT,
                        label + "必须为纯数字，实际为 " + value);
            }
        }
    }
}
