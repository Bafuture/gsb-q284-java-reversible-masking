package com.example.gsb.mask;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class MaskingServiceTest {

    private static final String PHONE = "phone";
    private static final String IDCARD = "idCard";
    private static final String NAME = "name";

    private MaskingService newService(Keyring keyring) {
        return MaskingService.builder()
                .keyring(keyring)
                .field(FieldSpec.of(PHONE, FormatType.PHONE))
                .field(FieldSpec.of(IDCARD, FormatType.ID_CARD))
                .field(FieldSpec.of(NAME, FormatType.GENERIC))
                .build();
    }

    private MaskingService newService() {
        return newService(Keyring.of("v1", "test-secret-key-0001"));
    }

    // 1. 确定性映射：同一原值同一密钥下结果一致且幂等
    @Test
    void deterministicMapping_sameValueSameToken() {
        MaskingService service = newService();
        String first = service.mask(PHONE, "13800138000");
        String second = service.mask(PHONE, "13800138000");
        assertThat(first).isEqualTo(second);
        assertThat(first).isNotEqualTo("13800138000");
        assertThat(service.stats().mappingCount()).isEqualTo(1);

        // 不同原值映射为不同结果
        String other = service.mask(PHONE, "13900139000");
        assertThat(other).isNotEqualTo(first);
        assertThat(service.stats().mappingCount()).isEqualTo(2);

        // 不同密钥下同一原值结果不同
        MaskingService otherKey = newService(Keyring.of("v1", "another-secret-key-9"));
        assertThat(otherKey.mask(PHONE, "13800138000")).isNotEqualTo(first);
    }

    // 2. 授权还原成功
    @Test
    void authorizedUnmask_restoresOriginal() {
        MaskingService service = newService();
        String token = service.mask(PHONE, "13800138000");
        String restored = service.unmask(PHONE, token, Authorization.forFields(PHONE));
        assertThat(restored).isEqualTo("13800138000");
        assertThat(service.stats().unmaskCount()).isEqualTo(1);
    }

    // 2. 无授权必须失败并说明原因
    @Test
    void unauthorizedUnmask_failsWithReason() {
        MaskingService service = newService();
        String token = service.mask(PHONE, "13800138000");

        // 授权了别的字段
        assertThatThrownBy(() -> service.unmask(PHONE, token, Authorization.forFields(NAME)))
                .isInstanceOf(MaskingException.class)
                .hasMessageContaining(RejectionReason.UNAUTHORIZED_FIELD.message());

        // 授权范围不含该密钥版本
        assertThatThrownBy(() -> service.unmask(PHONE, token,
                Authorization.forVersions(Set.of(PHONE), Set.of("v999"))))
                .isInstanceOf(MaskingException.class)
                .hasMessageContaining(RejectionReason.UNAUTHORIZED_KEY_VERSION.message());

        // 未知映射值
        assertThatThrownBy(() -> service.unmask(PHONE, "19999999999",
                Authorization.forFields(PHONE)))
                .isInstanceOf(MaskingException.class)
                .hasMessageContaining(RejectionReason.UNKNOWN_TOKEN.message());

        assertThat(service.stats().unmaskCount()).isZero();
    }

    // 3. 跨数据集一致：同一字段在不同数据集中映射结果一致
    @Test
    void crossDatasetConsistency() {
        MaskingService service = newService();
        List<String> datasetA = List.of("13800138000", "13900139000");
        List<String> datasetB = List.of("13900139000", "13700137000");

        List<String> maskedA = datasetA.stream().map(v -> service.mask(PHONE, v)).toList();
        List<String> maskedB = datasetB.stream().map(v -> service.mask(PHONE, v)).toList();

        // 交集值 13900139000 在两个数据集中映射一致，可关联
        assertThat(maskedA.get(1)).isEqualTo(maskedB.get(0));
        assertThat(service.stats().mappingCount()).isEqualTo(3);

        // 两个独立服务实例共用同一保险库时同样一致
        MappingVault shared = new MappingVault();
        Keyring keyring = Keyring.of("v1", "shared-secret-key-01");
        MaskingService svc1 = MaskingService.builder().keyring(keyring)
                .sharedVault(shared).field(FieldSpec.of(PHONE, FormatType.PHONE)).build();
        MaskingService svc2 = MaskingService.builder().keyring(keyring)
                .sharedVault(shared).field(FieldSpec.of(PHONE, FormatType.PHONE)).build();
        assertThat(svc1.mask(PHONE, "13800138000")).isEqualTo(svc2.mask(PHONE, "13800138000"));
    }

    // 4. 密钥轮换：老数据仍可还原，新数据用新密钥
    @Test
    void keyRotation_oldDataStillUnmaskable() {
        Keyring keyring = Keyring.of("v1", "rotation-secret-v1-01");
        MaskingService service = newService(keyring);

        String oldToken = service.mask(PHONE, "13800138000");
        keyring.rotate(KeyVersion.of("v2", "rotation-secret-v2-02"));

        String newToken = service.mask(PHONE, "13800138000");
        assertThat(newToken).isNotEqualTo(oldToken);

        Authorization auth = Authorization.forFields(PHONE);
        assertThat(service.unmask(PHONE, oldToken, auth)).isEqualTo("13800138000");
        assertThat(service.unmask(PHONE, newToken, auth)).isEqualTo("13800138000");
        assertThat(service.stats().keyVersionCount()).isEqualTo(2);

        // 只允许新版本授权时，老数据还原被拒绝
        assertThatThrownBy(() -> service.unmask(PHONE, oldToken,
                Authorization.forVersions(Set.of(PHONE), Set.of("v2"))))
                .isInstanceOf(MaskingException.class)
                .hasMessageContaining(RejectionReason.UNAUTHORIZED_KEY_VERSION.message());
    }

    // 5. 格式保持：手机号/身份证保持长度与字符类型
    @Test
    void formatPreservation() {
        MaskingService service = newService();

        String phone = service.mask(PHONE, "13800138000");
        assertThat(phone).hasSize(11).matches("\\d{11}");

        String idWithDigit = service.mask(IDCARD, "110101199003077758");
        assertThat(idWithDigit).hasSize(18).matches("\\d{18}");

        String idWithX = service.mask(IDCARD, "11010119900307775X");
        assertThat(idWithX).hasSize(18).matches("\\d{17}X");

        // 非法格式被拒绝并说明原因
        assertThatThrownBy(() -> service.mask(PHONE, "138-0013-8000"))
                .isInstanceOf(MaskingException.class)
                .hasMessageContaining(RejectionReason.INVALID_FORMAT.message());
        assertThatThrownBy(() -> service.mask(IDCARD, "1101011990030777"))
                .isInstanceOf(MaskingException.class)
                .hasMessageContaining(RejectionReason.INVALID_FORMAT.message());

        // 格式保持的映射值仍可还原
        assertThat(service.unmask(IDCARD, idWithX, Authorization.forFields(IDCARD)))
                .isEqualTo("11010119900307775X");
    }

    // 6. 碰撞检测：REJECT 策略下报告并拒绝
    @Test
    void collisionDetection_rejectPolicy() {
        MaskingService service = MaskingService.builder()
                .keyring(Keyring.of("v1", "collision-secret-001"))
                .field(FieldSpec.of(NAME, FormatType.GENERIC))
                .deriver(constantDeriver())
                .collisionPolicy(CollisionPolicy.REJECT)
                .build();

        String token = service.mask(NAME, "alice");
        assertThat(service.mask(NAME, "alice")).isEqualTo(token); // 幂等，不触发碰撞

        assertThatThrownBy(() -> service.mask(NAME, "bob"))
                .isInstanceOf(MaskingException.class)
                .hasMessageContaining(RejectionReason.COLLISION_REJECTED.message())
                .hasMessageContaining("alice")
                .hasMessageContaining("bob");

        assertThat(service.stats().collisionCount()).isEqualTo(1);
        assertThat(service.stats().collisionEvents()).hasSize(1);
        CollisionEvent event = service.stats().collisionEvents().get(0);
        assertThat(event.field()).isEqualTo(NAME);
        assertThat(event.firstValue()).isEqualTo("alice");
        assertThat(event.incomingValue()).isEqualTo("bob");
        assertThat(event.keyVersionId()).isEqualTo("v1");
    }

    // 6. 碰撞检测：RETRY 策略下自动换结果并保留碰撞记录
    @Test
    void collisionDetection_retryPolicy() {
        MaskingService service = MaskingService.builder()
                .keyring(Keyring.of("v1", "collision-secret-002"))
                .field(FieldSpec.of(NAME, FormatType.GENERIC))
                .deriver(retryableDeriver())
                .collisionPolicy(CollisionPolicy.RETRY)
                .maxRetries(4)
                .build();

        String alice = service.mask(NAME, "alice");
        String bob = service.mask(NAME, "bob");
        assertThat(bob).isNotEqualTo(alice);
        assertThat(service.stats().collisionCount()).isEqualTo(1);

        Authorization auth = Authorization.forFields(NAME);
        assertThat(service.unmask(NAME, alice, auth)).isEqualTo("alice");
        assertThat(service.unmask(NAME, bob, auth)).isEqualTo("bob");
    }

    // 6. 碰撞检测：重试耗尽仍失败并说明原因
    @Test
    void collisionDetection_retryExhausted() {
        MaskingService service = MaskingService.builder()
                .keyring(Keyring.of("v1", "collision-secret-003"))
                .field(FieldSpec.of(NAME, FormatType.GENERIC))
                .deriver(constantDeriver())
                .collisionPolicy(CollisionPolicy.RETRY)
                .maxRetries(3)
                .build();

        service.mask(NAME, "alice");
        assertThatThrownBy(() -> service.mask(NAME, "bob"))
                .isInstanceOf(MaskingException.class)
                .hasMessageContaining(RejectionReason.RETRY_EXHAUSTED.message());
        assertThat(service.stats().collisionCount()).isEqualTo(1);
    }

    // 7. 统计：映射条数、还原次数、密钥版本数、碰撞数
    @Test
    void stats_areTracked() {
        Keyring keyring = Keyring.of("v1", "stats-secret-key-001");
        MaskingService service = newService(keyring);

        String t1 = service.mask(PHONE, "13800138000");
        service.mask(PHONE, "13900139000");
        service.mask(IDCARD, "110101199003077758");
        keyring.rotate(KeyVersion.of("v2", "stats-secret-key-002"));
        service.mask(PHONE, "13700137000");

        Authorization auth = Authorization.forFields(PHONE, IDCARD);
        service.unmask(PHONE, t1, auth);
        service.unmask(PHONE, t1, auth);

        assertThat(service.stats().mappingCount()).isEqualTo(4);
        assertThat(service.stats().unmaskCount()).isEqualTo(2);
        assertThat(service.stats().keyVersionCount()).isEqualTo(2);
        assertThat(service.stats().collisionCount()).isZero();
    }

    // 未注册字段被拒绝
    @Test
    void unknownField_rejected() {
        MaskingService service = newService();
        assertThatThrownBy(() -> service.mask("address", "some address"))
                .isInstanceOf(MaskingException.class)
                .hasMessageContaining(RejectionReason.UNKNOWN_FIELD.message());
    }

    /** 恒定输出派生器：任何输入都得到同一令牌，用于强制碰撞。 */
    private static TokenDeriver constantDeriver() {
        return (field, value, key, attempt) -> new byte[32];
    }

    /** attempt=0 时恒定输出（强制首次碰撞），重试时按 SHA-256 分散。 */
    private static TokenDeriver retryableDeriver() {
        return (field, value, key, attempt) -> {
            if (attempt == 0) {
                return new byte[32];
            }
            try {
                return MessageDigest.getInstance("SHA-256")
                        .digest((field + ":" + value + ":" + attempt)
                                .getBytes(StandardCharsets.UTF_8));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        };
    }
}
