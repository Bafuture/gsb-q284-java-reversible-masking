# 可逆脱敏与映射还原组件

Pair-wise GSB 标注任务仓库（第 17 批 / 284）。

| 项目 | 内容 |
|------|------|
| 任务类型 | Feature 迭代 |
| 任务难度 | 困难 |
| 语言/框架 | Java, Maven, JUnit 5 |
| 环境可复现等级 | 无外部依赖 |
| 构建方式 | Maven（含 mvnw wrapper，无需本机安装 Maven） |

> 本仓库是**初始环境快照**：只有工程骨架，不含任何实现代码。
> 分支说明：`main` 为初始环境；`A`、`B` 为两次独立执行各自的工作分支，均从 `main` 的同一个提交拉出。

## 运行方式

```bash
./mvnw -q verify
```

## 任务提示词

以下为本题完整的 User Prompt 原文，两次执行必须使用完全相同的文本。

我们的数据要给分析团队用，但真实值不能出库，同时业务偶尔需要按授权还原原值。请从零实现一个可逆脱敏与映射还原组件。仓库目前只有一个空的 Maven 工程（pom.xml 只声明 JUnit 5 与 AssertJ）。要求：1) 支持对指定字段做可逆脱敏：用确定性映射把原值替换为不可识别的等价表示，同一原值在同一密钥下必须映射为同一结果；2) 支持还原：持有密钥与授权时可把映射值还原为原值，无授权时必须失败并说明原因；3) 支持一致性：同一字段在不同数据集中出现时映射结果一致，保证关联分析可行；4) 支持密钥轮换：换密钥后老数据仍能还原（保留历史密钥或版本标识），新数据用新密钥；5) 支持格式保持：对手机号、身份证这类有格式要求的值，脱敏后仍需保持长度与字符类型，便于下游校验；6) 支持碰撞检测：不同原值映射为同一结果时必须能检测并报告；7) 提供统计：映射条数、还原次数、密钥版本数与检测到的碰撞数；8) 测试覆盖确定性映射、授权还原与拒绝、跨数据集一致、密钥轮换、格式保持与碰撞检测；`mvn -q verify` 一条命令跑通。

## 提交要求

1. 在本仓库中完成提示词要求的全部内容。
2. `./mvnw -q verify` 必须通过。
3. 完成后在所属分支（A 或 B）上提交，产物快照的父提交必须是初始环境快照。

## 实现说明（B 分支）

组件位于 `com.example.gsb.mask` 包下，核心类：

| 类 | 职责 |
|----|------|
| `MaskingService` | 脱敏/还原入口，`mask(field, value)` 与 `unmask(field, token, authorization)` |
| `Keyring` / `KeyVersion` | 版本化密钥环，轮换后历史版本保留用于还原老数据 |
| `MappingVault` | 双向映射保险库（受信、不出库），负责一致性映射与碰撞检测 |
| `Authorization` | 字段级 + 密钥版本级还原授权 |
| `FormatType` | 格式保持：PHONE（纯数字定长）、ID_CARD（17 位数字 + 数字/X 末位）、GENERIC |
| `TokenDeriver` / `HmacTokenDeriver` | 确定性令牌派生（HmacSHA256），可注入自定义实现 |
| `CollisionPolicy` | 碰撞策略：REJECT（拒绝并报告）/ RETRY（换参数重试） |
| `MaskingStats` | 统计：映射条数、还原次数、密钥版本数、碰撞数与碰撞明细 |

### 用法示例

```java
Keyring keyring = Keyring.of("v1", "my-secret-key");
MaskingService service = MaskingService.builder()
        .keyring(keyring)
        .field(FieldSpec.of("phone", FormatType.PHONE))
        .field(FieldSpec.of("idCard", FormatType.ID_CARD))
        .collisionPolicy(CollisionPolicy.REJECT)
        .build();

String masked = service.mask("phone", "13800138000");          // 定长数字，确定性
String plain  = service.unmask("phone", masked,
        Authorization.forFields("phone"));                     // 无授权抛 MaskingException

keyring.rotate(KeyVersion.of("v2", "my-new-secret-key"));      // 轮换：新数据用 v2，老数据仍可还原
```

多个数据集（或同一进程内多个服务实例）共用同一个 `MappingVault`
（`builder().sharedVault(vault)`）即可保证同一字段跨数据集映射一致。

### 验证

```bash
mvn -q verify   # 11 个测试全部通过
```
