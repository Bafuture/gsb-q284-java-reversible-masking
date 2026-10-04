package com.example.gsb.masking;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MaskingServiceTest {

    private static byte[] key(String secret) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        byte[] padded = new byte[32];
        System.arraycopy(bytes, 0, padded, 0, Math.min(bytes.length, 32));
        return padded;
    }

    private static MaskingService service(byte[] key, String... grantees) {
        return new MaskingService(key, AuthorizationPolicy.allow(Set.of(grantees)));
    }

    @Test
    void deterministicMapping_sameValueSameToken_differentValuesDiffer() {
        MaskingService svc = service(key("v1-key"), "analyst");

        MaskedValue first = svc.mask("phone", "13800138000");
        MaskedValue second = svc.mask("phone", "13800138000");
        MaskedValue other = svc.mask("phone", "13900139000");

        assertThat(second.token()).isEqualTo(first.token());
        assertThat(second.keyVersion()).isEqualTo(first.keyVersion());
        assertThat(other.token()).isNotEqualTo(first.token());
    }

    @Test
    void genericFormat_isAlsoDeterministicAndReversible() {
        MaskingService svc = service(key("v1-key"), "analyst");

        MaskedValue a = svc.mask("name", "张三", FieldFormat.GENERIC);
        MaskedValue b = svc.mask("name", "张三", FieldFormat.GENERIC);

        assertThat(a.token()).isEqualTo(b.token());
        assertThat(svc.reveal(a, new Authorization("analyst"))).isEqualTo("张三");
    }

    @Test
    void reveal_withAuthorization_returnsOriginalValue() {
        MaskingService svc = service(key("v1-key"), "analyst-li");
        MaskedValue masked = svc.mask("phone", "13800138000");

        String original = svc.reveal(masked, new Authorization("analyst-li"));

        assertThat(original).isEqualTo("13800138000");
    }

    @Test
    void reveal_withoutAuthorization_isDeniedWithReason() {
        MaskingService svc = service(key("v1-key"), "analyst-li");
        MaskedValue masked = svc.mask("phone", "13800138000");

        assertThatThrownBy(() -> svc.reveal(masked, new Authorization("intern-wang")))
                .isInstanceOf(UnauthorizedRevealException.class)
                .hasMessageContaining("reveal denied")
                .hasMessageContaining("intern-wang")
                .hasMessageContaining("phone");

        // denied reveals must not be counted
        assertThat(svc.statistics().revealCount()).isZero();
    }

    @Test
    void crossDatasetConsistency_sameFieldAndKeyYieldsSameToken() {
        byte[] sharedKey = key("shared-corp-key");
        MaskingService datasetA = service(sharedKey, "analyst");
        MaskingService datasetB = service(sharedKey, "analyst");

        MaskedValue fromA = datasetA.mask("phone", "13800138000");
        MaskedValue fromB = datasetB.mask("phone", "13800138000");

        assertThat(fromB.token()).isEqualTo(fromA.token());
        assertThat(fromB.keyVersion()).isEqualTo(fromA.keyVersion());
        // unrelated field gets a different mapping
        MaskedValue otherField = datasetA.mask("id_card", "13800138000");
        assertThat(otherField.token()).isNotEqualTo(fromA.token());
    }

    @Test
    void keyRotation_oldDataStaysRevealable_newDataUsesNewKey() {
        MaskingService svc = service(key("old-key"), "analyst");
        MaskedValue oldMasked = svc.mask("phone", "13800138000");
        String oldToken = oldMasked.token();

        int newVersion = svc.rotateKey(key("new-key"));
        assertThat(newVersion).isEqualTo(2);

        MaskedValue newMasked = svc.mask("phone", "13800138000");
        assertThat(newMasked.keyVersion()).isEqualTo(2);
        assertThat(newMasked.token()).isNotEqualTo(oldToken);

        // both versions still reveal to the same original
        assertThat(svc.reveal(oldMasked, new Authorization("analyst")))
                .isEqualTo("13800138000");
        assertThat(svc.reveal(newMasked, new Authorization("analyst")))
                .isEqualTo("13800138000");
        assertThat(svc.statistics().keyVersionCount()).isEqualTo(2);
    }

    @Test
    void reveal_withRetiredKeyVersion_failsWithReason() {
        MaskingService svc = service(key("v1-key"), "analyst");
        MaskedValue masked = svc.mask("phone", "13800138000");

        // token produced under a key version this service no longer holds
        MaskedValue stale = new MaskedValue("phone", 99,
                FieldFormat.FORMAT_PRESERVING, masked.token());

        assertThatThrownBy(() -> svc.reveal(stale, new Authorization("analyst")))
                .isInstanceOf(UnknownKeyVersionException.class)
                .hasMessageContaining("key version 99");
    }

    @Test
    void formatPreserving_keepsLengthAndCharacterClasses() {
        MaskingService svc = service(key("v1-key"), "analyst");

        MaskedValue phone = svc.mask("phone", "13800138000");
        assertThat(phone.token()).hasSize(11).matches("[0-9]{11}");
        assertThat(phone.token()).isNotEqualTo("13800138000");

        MaskedValue idCard = svc.mask("id_card", "11010119900307753X");
        assertThat(idCard.token()).hasSize(18);
        assertThat(idCard.token().substring(0, 17)).matches("[0-9]{17}");
        // checksum char keeps its character class (uppercase letter)
        assertThat(String.valueOf(idCard.token().charAt(17))).matches("[A-Z]");
        assertThat(idCard.token()).isNotEqualTo("11010119900307753X");

        // round trip
        assertThat(svc.reveal(phone, new Authorization("analyst"))).isEqualTo("13800138000");
        assertThat(svc.reveal(idCard, new Authorization("analyst")))
                .isEqualTo("11010119900307753X");
    }

    @Test
    void collisionDetection_reportsDistinctOriginalsSharingToken() {
        TokenCipher constantCipher = new TokenCipher() {
            @Override
            public String encrypt(byte[] key, String field, FieldFormat format, String value) {
                return "SAME-TOKEN";
            }

            @Override
            public String decrypt(byte[] key, String field, FieldFormat format, String token) {
                return token;
            }
        };
        MaskingService svc = new MaskingService(new KeyStore(key("v1-key")), constantCipher,
                AuthorizationPolicy.allow(Set.of("analyst")));

        svc.mask("phone", "13800138000");
        svc.mask("phone", "13900139000"); // forced onto the same token

        assertThat(svc.detectedCollisions()).hasSize(1);
        Collision collision = svc.detectedCollisions().get(0);
        assertThat(collision.field()).isEqualTo("phone");
        assertThat(collision.token()).isEqualTo("SAME-TOKEN");
        assertThat(collision.existingValue()).isEqualTo("13800138000");
        assertThat(collision.newValue()).isEqualTo("13900139000");
        assertThat(svc.statistics().collisionCount()).isEqualTo(1);
    }

    @Test
    void statisticsTrackMappedRevealKeyVersionAndCollisionCounters() {
        MaskingService svc = service(key("v1-key"), "analyst");
        svc.mask("phone", "13800138000");
        svc.mask("phone", "13800138000"); // repeat -> deterministic, no collision
        svc.mask("phone", "13700137000");
        svc.reveal(svc.mask("name", "王五", FieldFormat.GENERIC),
                new Authorization("analyst"));
        svc.rotateKey(key("v2-key"));

        MaskingStatistics stats = svc.statistics();
        assertThat(stats.mappedCount()).isEqualTo(4L);
        assertThat(stats.revealCount()).isEqualTo(1L);
        assertThat(stats.keyVersionCount()).isEqualTo(2);
        assertThat(stats.collisionCount()).isZero();
    }
}
