# MoonTLCP 安全审计与对抗加固报告（Security Audit Report）

> 审计范围：`CoolrfulDARkness/moontlcp` 全仓（`crypto/{ct,sm3,sm4,sm2}`、`x509/{der,.}`、`record`、`handshake`、`state`、`sm9/*`、`web_api`）  
> 审计方法：白盒密码学与协议状态机红队代码审查 + 自动化对抗回归（`state/adversarial_test.mbt` 26 项 TLCP 对抗用例 + `sm9/*_test.mbt` SM9 畸形点/子群/IND-CCA2 对抗用例）+ OpenSSL 3.5.6 实时双向 8/8 跨语言字节级对拍。

---

## 1. 审计总览与安全基线

| 维度 | 当前状态 | 自动化验证位置 |
| :--- | :--- | :--- |
| **内存与类型安全** | 100% 纯 MoonBit，零 C/FFI、零 `unsafe`、零外部依赖 | `moon.mod`、`moon check -d`（0 warnings） |
| **TLCP 1.1 协议对抗回归** | **26/26 PASS**（覆盖密文/Tag/Padding/Nonce 篡改、版本降级、双证互换、伪造签名、重放、DoS、mTLCP 复用隔离、Fail-Closed） | `state/adversarial_test.mbt` |
| **SM9 BN256 密码对抗回归** | **全量 PASS**（覆盖非曲线点、超界坐标、无穷远点、wrong-twist、G2 cofactor 攻击、伪造签名/确认标签、IND-CCA2 统一报错、弱熵/超大 KDF 拒绝） | `sm9/{ec,sign,keyex,enc}/*_test.mbt` |
| **跨语言互操作对拍** | **OpenSSL 3.5.6 双向 8/8 PASS**（SM3/SM4/SM2/X.509 双证书链） | `harness/interop_openssl.py` |
| **核心密码零重复审计** | **0 处重复实现**（全仓唯一 `crypto/sm3` 压缩核、唯一 `crypto/sm4` S-box 与轮密钥核、唯一 `crypto/ct` 原语） | `docs/ARCHITECTURE.md` §1.1 |

---

## 2. 真实发现与修复清单（P0 / P1 Findings）

以下所有安全缺陷均在本项目红队对抗审计与架构整合过程中真实定位、完成代码修复，并固化为永久回归测试（任意回退均会被 CI 三端门禁立即阻断）：

### [AUD-01 · P0] 握手消息重组无上限导致的内存耗尽 DoS
- **风险描述**：攻击者可发送声称 24-bit 长度为 `0xFFFFFF`（约 16 MiB）的伪造握手帧头，诱使对端无限制缓存握手分片造成 OOM / 拒绝服务。
- **修复措施**：在 `handshake/messages.mbt` 定义并强制校验 `MAX_HANDSHAKE_MSG_LEN = 65536`（64 KiB），记录层同步强制 `MAX_CIPHERTEXT_LEN = 18432`（`record/record.mbt`）；超限帧在头部解析阶段即刻拒绝，下发 `DecodeError` / `RecordOverflow` Fatal Alert 并锁死 `Failed` 态。
- **回归验证**：`state/adversarial_test.mbt` — `adversarial 22`（`>18432B` 记录溢出）、`adversarial 23`（`>64KiB` 握手帧 DoS）。

### [AUD-02 · P0] SM4-GCM 显式 Nonce 构造与序列号状态一致性（RFC 5288）
- **风险描述**：GCM AEAD 严禁同一密钥下 Nonce 重复或可预测碰撞；若解密失败仍推进 `seq_num` 或显式 Nonce 未与 `seq_num` 严格绑定，将引入重放或状态失步风险。
- **修复措施**：
  1. 严格按 **RFC 5288 / GM/T 0024-2023** 将 8 字节显式 Nonce 设为当前 64-bit 大端 `seq_num`，与 4 字节隐式 IV 拼接构成唯一 12 字节 Nonce；
  2. `RecordLayer::seal` / `RecordLayer::open` 检查 `MAX_SEQ_NUM = 0xFFFFFFFFFFFFFFFFUL` 防止回绕，且**仅在加密编码或 AEAD 鉴权完全通过后**才自增 `seq`（`record/record.mbt:414, 578`）。
- **回归验证**：`state/adversarial_test.mbt` — `adversarial 02`、`adversarial 04`、`adversarial 14`（重放拦截）、`adversarial 24`（校验显式 Nonce 严格等于 `seq_num`）。

### [AUD-03 · P0] 双向认证（mTLCP）会话复用身份绑定绕过防护
- **风险描述**：若单向认证建立的缓存会话（无客户端双证书身份）被提交至要求双向认证（`require_client_cert = true`）的服务端，或客户端传入畸形长度的 `ResumedSession`，可能导致认证策略绕过或派生异常。
- **修复措施**：
  1. `state/server.mbt:380` 强制校验 `let mtlcp_ok = !self.config.require_client_cert || !(rs.peer_certs is None)`，无客户端双证绑定的会话绝不允许在 mTLCP 服务端复用；
  2. `state/client.mbt:243` 与服务端统一执行 `is_valid_resumed_session`，拒绝 `session_id` 长度不在 `1..=32` 或 `master_secret` 非 48 字节的非法会话。
- **回归验证**：`state/adversarial_test.mbt` — `adversarial 25`。

### [AUD-04 · P0] CA 证书冒充终端叶子证书与 TLCP 双证书用途分离（GM/T 0024 §6.4.5.2）
- **风险描述**：
  1. 若握手链解析仅验签而不校叶子证书的 `BasicConstraints.cA`，攻击者可能将 CA 证书置于叶子槽位；
  2. TLCP 1.1 要求签名证书（`certificates[0]`）与加密证书（`certificates[1]`）用途严格分离，互换或混用会破坏不可否认性与密钥托管隔离。
- **修复措施**：
  1. `x509/dual_cert.mbt:168-177` 显式拒绝 `sign_cert.is_ca == true` 与 `enc_cert.is_ca == true`（抛出 `BadKeyUsage`）；
  2. `check_sign_cert_usage` 与 `check_enc_cert_usage` 强制校对 `digitalSignature` 与 `keyEncipherment`/`dataEncipherment`/`keyAgreement`，检测双证互换立即抛出 `DualCertMismatch` → `BadCertificate` Fatal Alert；
  3. 空 `trust_anchors` 默认 Fail-Closed 拒绝。
- **回归验证**：`state/adversarial_test.mbt` — `adversarial 08`、`adversarial 09`；`x509/x509_test.mbt`；浏览器红队一键复现（`swap_dual_certs`）。

### [AUD-05 · P0] SM4-CBC-HMAC-SM3 抗 Lucky13 与 Padding Oracle 恒定时间解密
- **风险描述**：TLCP 1.1 CBC 套件（`0xE011`/`0xE013`）采用 MAC-then-Encrypt，若解密时先检查填充长度再早退、按变长读取 MAC 或因明文长度变化导致 SM3 压缩块数差异，将暴露 Lucky13 远程时序侧信道。
- **修复措施**（`record/record.mbt:470-532`）：
  1. 恒定时间验证至多 256 字节填充内容与边界（`@ct.ct_lt_u32` / `@ct.ct_eq_u32` / `@ct.ct_select_u32`），填充错误不提前返回而是无分支回退至 `fallback_pt_len = n - 33`；
  2. 在公开固定窗口 `[scan_start, n - 33]` 上用 `@ct.ct_select_byte` 恒定时间提取 32 字节 `received_mac`；
  3. 计算实际 HMAC-SM3 后，按 SM3 64 字节分组上限计算 `extra_blocks = max_blocks - actual_blocks`，执行等量哑压缩块对齐，抹平不同填充长度导致的哈希压缩轮数差异；
  4. 合并 `pad_good & mac_ok`，所有填充错误与 MAC 错误统一抛出 `BadRecordMac` Fatal Alert。
- **回归验证**：`state/adversarial_test.mbt` — `adversarial 01`、`adversarial 03`、`record/record_test.mbt`。

### [AUD-06 · P1] 握手边界残留注入、协议降级与 Fail-Closed 永久锁死
- **风险描述**：攻击者可在 `Finished` 同一加密记录末尾追加未认证握手字节、在 `CloseNotify` 后继续注入应用数据、或发送 TLS 1.2 (`0x0303`) / TLCP 1.0 (`0x0100`) 降级报文。
- **修复措施**：
  1. `Finished` 处理完成后断言 `hs_buf` 必须为空，否则立即触发 Fatal Alert；
  2. 收到 `CloseNotify` 置位 `peer_closed`，后续 `ApplicationData` 一律抛出 `UnexpectedMessage`；
  3. 记录层与握手层双层强制 `0x0101`（`TLCP_VERSION_MAJOR/MINOR`），拒绝 `0x0303` / `0x0100`；
  4. 任意 Fatal 错误后连接永久转入 `Failed` 态，拒绝一切后续 `feed` / `write_app_data` / `close_notify`。
- **回归验证**：`state/adversarial_test.mbt` — `adversarial 05`、`06`、`07`、`15`、`16`、`17`、`21`、`24`、`26`。

### [AUD-07 · P1] 静态 ECC `ServerKeyExchange` 加密证书绑定与 Strict DER 规范化
- **风险描述**：静态 `ECC_SM4_*` 套件若缺失 `ServerKeyExchange` 对加密证书的签名验证，中间人可替换加密证书；非规范 BER 编码（不定长、冗余前导零、显式编码默认值）可引发解析器分歧攻击。
- **修复措施**：严格按 GB/T 38636 §6.4.5.4 校验 `client_random || server_random || uint24(len(enc_cert)) || enc_cert` 的 SM2-with-SM3 签名；`x509/der` 执行 ITU-T X.690 Strict DER 解析，并在 `harness/interop_openssl.py` 与 OpenSSL 3.5.6 逐字节重编码比对验证。
- **回归验证**：`state/adversarial_test.mbt` — `adversarial 10`、`11`；`x509/der/der_test.mbt`；OpenSSL 3.5.6 8/8 对拍。

### [AUD-08 · P1] SM9 BN256 子群校验、IND-CCA2 密文防护与共享核零重复验证
- **风险描述**：
  1. BN256 的扭转曲线 `G2` 存在非素数阶余因子（cofactor），未校子群的伪造点可引发小群/无效曲线攻击；
  2. SM9 PKE 解密若区分 `C1` 错误、`K1==0`、`C3` MAC 错误与 PKCS#7 填充错误，会暴露 IND-CCA2 预言机；
  3. 同仓并存多份 SM3/SM4 实现会导致侧信道修复漂移。
- **修复措施**：
  1. `sm9/ec` 在 `G2Affine` 反序列化入口强制执行 `is_in_subgroup` 素数阶子群检验，拦截 wrong-twist 与 cofactor 攻击；
  2. `sm9/enc::decrypt` 对所有校验失败统一返回 `Err("decryption failed")`，且强制加密熵 `>= 32B`、KDF 长度 `<= 16 MiB`；
  3. 静态审查确认 `sm9/hash` 100% 委托 `crypto/sm3` + `crypto/ct`，`sm9/enc` 直调 `crypto/sm4::Sm4Key::ecb_*_pkcs7`，全仓 0 处重复 SM3 压缩或 SM4 S-box 实现。
- **回归验证**：`sm9/{ec,sign,keyex,enc}/*_test.mbt`、`sm9/sm9_test.mbt`。

---

## 3. 威胁模型与明确非目标（Threat Model & Non-Goals）

### 3.1 威胁模型（本库防御什么）
- **主动网络攻击者（Dolev-Yao）**：窃听、截断、重放、乱序注入、1-bit 密文/Tag/Finished 篡改、版本降级（TLS 1.2 / TLCP 1.0）、双证书互换、伪造 CA 或伪造签名。
- **远程时序与预言机攻击**：CBC Lucky13 / Padding Oracle、SM9 PKE IND-CCA2 解密预言机、SM2/SM9 标量乘秘密依赖分支与查表泄漏。
- **解析器与内存安全攻击**：畸形 ASN.1 BER/DER、超大记录/握手帧 DoS、缓冲区越界（由 MoonBit 内存安全语言模型根除）。

### 3.2 诚实边界与非目标（Non-Goals & Limitations）
1. **JIT / Wasm / JS 运行时恒定时间边界**：本库在算法与源码层使用 `crypto/ct` 无分支掩码与固定窗口扫描消除秘密依赖分支和内存索引，但 **Wasm/JS 引擎的 JIT 编译器与底层 CPU 微架构行为**不受纯高级语言源码完全控制。对需要抵御本地共置微架构侧信道（Flush+Reload / Spectre / 功耗分析）的高敏场景，建议编译至 Native 目标并在独立信任域或硬件密码模块（HSM/SDF）内运行。
2. **随机数熵源由宿主注入**：为保持零 FFI 与纯 Sans-I/O 跨平台可复现性，本库不直接调用 OS CSPRNG；生产部署**必须**由宿主从操作系统密码学安全随机源（如 `getrandom` / `BCryptGenRandom` / `crypto.getRandomValues`）注入高熵 `seed` 与 ≥32B `entropy`。
3. **非目标项**：不包含 DTLCP（UDP）、异步 Socket 运行时绑定、PKCS#11/SKF/SDF 硬件驱动、在线 CRL/OCSP 吊销检查与 OS 时钟校验（有效期字段已完整暴露供宿主校验）、会话重协商及 ZUC 套件。
