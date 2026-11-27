# MoonTLCP 决赛评委白板问答速查表（Defense Q&A Cheat Sheet）

> 针对决赛现场评委最可能深挖的 5 个硬核密码学与工程边界问题，提供“核心原理 + 代码精确落点 + 现场演示佐证”三段式应答口径。

---

## Q1：SM4-CBC-HMAC-SM3 的 Lucky13 防护具体是怎么实现的？如何处理填充检查、MAC 提取和 SM3 压缩块数差？

**一句话定调**：在 `record/record.mbt:470-532` 实现完整的 **“无早退恒定时间验填 + 固定公开窗口选 MAC + SM3 压缩块差值对齐”** 三重防线，并将填充错误与 MAC 错误合并为单一 `BadRecordMac` 出口。

- **步骤 1（恒定时间验填）**：不因 `pad_len` 非法提前返回。以固定上界 `min(n, 256)` 逐字节用 `@ct.ct_lt_u32`、`@ct.ct_eq_u32`、`@ct.ct_select_u32` 累积 `pad_good`；若填充非法，通过无分支 `ct_select_u32` 将有效明文长度 `pt_len` 回退为 `fallback_pt_len = n - 33`，确保后续仍执行完整 MAC 流程。
- **步骤 2（固定公开窗口提取 MAC）**：接收到的 32B `received_mac` 不直接按秘密偏移 `dec[pt_len..pt_len+32]` 切片读取，而是在仅依赖公开密文总长 `n` 的窗口 `[max(0, n - 288), n - 33]` 上线性扫描，逐字节以 `@ct.ct_select_byte(pos == pt_len, ...)` 无分支选出。
- **步骤 3（SM3 压缩块数对齐）**：Lucky13 的核心泄漏源是不同填充长度会跨越 64 字节哈希压缩块边界。代码按 `max_blocks = (13 + max_pos + 136) / 64` 与 `actual_blocks = (13 + pt_len + 136) / 64` 计算块数差 `extra_blocks`（其中 `136 = 64B ipad + 1B 0x80 + 8B 长度 + 63B 向上取整`），对临时 `Sm3` 执行 `extra_blocks` 次哑块压缩补齐耗时。
- **步骤 4（统一错误出口）**：最终仅判断 `(pad_good & mac_ok) == 0U`，统一抛出 `BadRecordMac` + Fatal Alert 并永久锁死连接（见 `state/adversarial_test.mbt` #01/#03）。

---

## Q2：SM2 底层椭圆曲线算术如何兼顾高性能与恒定时间？Solinas 约简与 4-bit 固定窗口怎么落地？

**一句话定调**：`crypto/sm2/field.mbt` 与 `crypto/sm2/curve.mbt` 采用 **8×32-bit 小端 limb + `UInt64` 中间积 + SM2 素数 Solinas 快速约简 + 4-bit 固定窗口恒定时间标量乘**，在纯 MoonBit 零 FFI 下 Native 单次 SM2 签验仅 ~2.5–3.3 ms。

- **Solinas 快速约简（`mod p`）**：利用 SM2 素数特殊结构 $p = 2^{256} - 2^{224} - 2^{96} + 2^{64} - 1$，将 512-bit 乘积高 8 个 32-bit limb 通过线性加减折叠约简到 256-bit，完全避免大整数除法；标量域 $\mathbb{F}_n$ 则使用 **CIOS Montgomery 乘法**。
- **恒定时间求逆与开方**：基于 Fermat 小定理（`p - 2`、`n - 2`）与固定加法链完成，全程无秘密依赖条件分支（区别于变步长扩展欧几里得）。
- **4-bit 固定窗口标量乘**：将 256-bit 标量切分为 64 个 4-bit 窗口，对预计算表 `[0P, 1P, ..., 15P]` 每次完整遍历全部 16 项并用 `jac_ct_select`（底层调用 `@ct.ct_select_u32`）无分支选出目标点，消除 SPA/缓存行索引泄漏；公开验签路径则采用 **Shamir's Trick**（双标量联合乘）加速。
- **签名防重用**：集成 **RFC 6979 确定性 nonce（HMAC-SM3）**，彻底杜绝弱随机数或 k 重用导致的私钥恢复漏洞。

---

## Q3：TLCP 1.1 双证书机制与 TLS 1.2/1.3 的核心差异是什么？如何防止用途混淆与版本降级？

**一句话定调**：TLCP 1.1（GM/T 0024 / GB/T 38636）为满足国密合规的“**签名不可否认性**与**加密密钥可托管恢复**分离”，在握手层强制要求服务端（及 mTLCP 客户端）同时提供**签名证书 + 加密证书**两张独立 X.509 v3 证书。

- **协议结构差异**：
  1. 版本号固定为 **`0x0101`**（不是 TLS 1.2 的 `0x0303`），记录层与握手层双层校验，收到 `0x0303` / `0x0100` 立即发送 `ProtocolVersion` Fatal Alert；
  2. `Certificate` 报文顺序强约束：`certificates[0]` 为签名证书、`certificates[1]` 为加密证书；
  3. 即使是静态 `ECC_SM4_*` 套件（`0xE013`/`0xE053`），服务端也**必须**发送 `ServerKeyExchange`，使用**签名私钥**对 `client_random || server_random || uint24(len(enc_cert)) || enc_cert` 签名以密码学绑定加密证书；
  4. `ECDHE_SM4_*` 套件（`0xE011`/`0xE051`）底层执行 **GB/T 32918.3 SM2 密钥交换（SM2-KE）**，按国标强制要求双向 mTLCP 认证。
- **防用途混淆实现**：`x509/dual_cert.mbt` 严格校验 `is_ca == false`（禁 CA 冒充叶子）、`certificates[0]` 须含 `digitalSignature`、`certificates[1]` 须含 `keyEncipherment`/`dataEncipherment`/`keyAgreement`；互换双证立即触发 `DualCertMismatch` → `BadCertificate` Fatal Alert。
- **现场演示**：可在交互工作台 Tab 1 一键点击 **「双证书互换冒充」** 现场展示拦截与 Fatal Alert 报文！

---

## Q4：SM9 BN256 双线性对如何实现？为什么说它与 TLCP 共享 SM3/SM4/CT 核心达到了“零重复”？

**一句话定调**：`sm9/` 实现了完整的 **GB/T 38635-2020 Part 1–5**（无需证书，邮箱即公钥），底层基于 BN256 扩域塔与最优 R-ate 双线性对，并且所有哈希、分组加密与恒定时间比较 100% 复用 TLCP 同一份 `crypto/{sm3,sm4,ct}`。

- **BN256 数学栈（`sm9/field`, `sm9/ec`, `sm9/pairing`）**：
  - 构建完整的 $\mathbb{F}_p \to \mathbb{F}_{p^2} \to \mathbb{F}_{p^6} \to \mathbb{F}_{p^{12}}$ 扩域塔（256-bit Montgomery 算术）；
  - 实现恒定时间 `G1` ($y^2=x^3+5$) 与扭转曲线 `G2` ($y^2=x^3+5u$) 标量乘，并在 `G2` 反序列化入口强制执行素数阶子群检验 `is_in_subgroup`，阻断 wrong-twist 与 cofactor 攻击；
  - 实现最优 R-ate Miller 循环 + 最终幂运算，并在验签等场景使用 `pair_product` 共享最终幂优化性能。
- **零重复共享核心实证**：
  - `sm9/hash` 仅为薄适配层（提供 `H1`/`H2` 320-bit 恒定时间精确约简、`KDF`、`MAC`、`Hv`），其 `Sm3` 与 `ct_eq_bytes` 100% 委托 `crypto/sm3` 与 `crypto/ct`；
  - `sm9/enc`（GB/T 38635.4 A.3 `Sm4EcbPkcs7`）直接依赖 `crypto/sm4` 调用恒定时间 PKCS#7 ECB 核；
  - 静态扫描全仓确认仅有 **1 份 SM3 压缩实现、1 份 SM4 S-box/轮密钥实现、1 份 CT 原语**，避免同一工程内密码库割裂与安全补丁漂移。

---

## Q5：纯 MoonBit 编译到 Wasm / JS / Native 后，如何看待 JIT/GC 环境下的恒定时间边界与生产部署限制？

**一句话定调**：我们坚持**诚实威胁模型（Honest Threat Model）**——源码层做到算法与访存恒定时间，同时明确划清高级语言运行时边界，绝不夸大“Wasm/JS 绝对免疫硬件侧信道”。

- **本库已提供的纵深防护**：通过 `crypto/ct` 无分支选择/比较、固定窗口标量乘、Lucky13 块数对齐与统一错误出口，彻底消除了算法层面的秘密依赖分支、秘密数组索引及可被远程网络观测的时序/预言机泄漏；纯 MoonBit 内存安全模型从根源上消除了 Heartbleed 类越界读与 C/C++ 内存破坏漏洞。
- **诚实承认的边界**：在浏览器 JS/Wasm JIT 或共享物理核场景下，JIT 优化器重排、GC 暂停与 CPU 微架构缓存行为无法由高级语言源码完全约束。因此：
  1. 我们在 `README.md` 与 `docs/SECURITY_AUDIT.md` 明确列出 **Threat Model & Non-Goals**；
  2. 对抗本地共置硬件微架构侧信道的高敏生产场景，建议编译至 **Native 目标** 并在隔离安全域 / 硬件密码卡（HSM/SDF）内执行根私钥运算；
  3. 本库坚持纯 Sans-I/O 零 FFI，调用方须负责注入 OS CSPRNG 高熵种子，并结合宿主可信时钟/OCSP/CRL 策略完成证书生命周期校验。
