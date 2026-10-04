package com.example.gsb.mask;

import java.util.Objects;

/** 字段脱敏策略：字段名 + 格式类型。 */
public record FieldSpec(String field, FormatType format) {

    public FieldSpec {
        Objects.requireNonNull(field, "field");
        Objects.requireNonNull(format, "format");
        if (field.isBlank()) {
            throw new IllegalArgumentException("field 不能为空");
        }
    }

    public static FieldSpec of(String field, FormatType format) {
        return new FieldSpec(field, format);
    }
}
