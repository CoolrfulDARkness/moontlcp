# moontlcp

**纯 MoonBit、零 C/FFI 依赖、类型安全的国密全栈安全基础设施：TLCP 1.1 双证书传输层协议（PKI） + SM9 BN256 标识密码全套算法（IBC），共享统一 SM3 / SM4 / CT 密码核心**

> 遵循 **GM/T 0024-2014 / GB/T 38636-2020（TLCP 1.1）**、**GB/T 38635-2020 / GM/T 0044-2016（SM9 Part 1–5）**、**GM/T 0015-2023**、**GB/T 32905-2016（SM3）**、**GB/T 32907-2016（SM4）**、**GB/T 32918-2016（SM2）** 与 **RFC 8998（SM4-GCM）**。  
> 一套零 FFI、零外部依赖纯 MoonBit 代码原生运行于 **WebAssembly (Wasm) / JavaScript (JS) / Native (MSVC/GCC)** 三端，**175 项核心全量测试零警告通过**，并通过 **OpenSSL 3.5.6 实时双向 8/8 跨语言字节级对拍**、**原生 `moonbitlang/async/socket` 并发 TLCP 1.1 反向代理（`examples/tlcp_async_proxy/`，5/5 Native TCP 闭环）**、**Node.js 真实 OS TCP Socket 端到端闭环** 与 **`examples/consumer` 已发布包外部消费验证（4/4）**。

- **在线零安装交互实验室（GitHub Pages）**：<https://coolrfuldarkness.github.io/moontlcp/>（浏览器内实时运行纯 MoonBit 编译的 TLCP 1.1 双证书握手显微镜、红队篡改攻防、Session ID 带宽对比与 SM9 邮箱即公钥交互台）
- **mooncakes.io 安装**：
  ```bash
  moon add CoolrfulDARkness/moontlcp
  ```

---

## 核心特性

- **零外部依赖、零 FFI、零 `unsafe`**：所有国密算法、双线性对、X.509 DER 解析与 Sans-I/O 状态机均 100% 纯 MoonBit 实现，天然杜绝 C/C++ 缓冲区溢出与 Heartbleed 类内存越界风险。
- **共享统一国密密码基座（零重复核心实现 + 恒定时间侧信道防护）**：
  - `crypto/ct`：恒定时间比较（`ct_eq`/`ct_eq_view`）、无分支比较/选择与清零原语，为 TLCP 记录层、SM2、SM4 及 SM9 统一复用。
  - `crypto/sm3`：**GB/T 32905-2016** 唯一流式/单次 SM3 压缩内核（含 `update_byte`/`reset`/`clone`）、RFC 2104 HMAC-SM3、GM/T 0024 `P_SM3` PRF、GB/T 32918.4 KDF。
  - `crypto/sm4`：**GB/T 32907-2016** 唯一 SM4 分组核，完整支持 **恒定时间 PKCS#7 ECB（供 SM9 Part 4 复用）**、**CBC**、**CTR** 以及 **RFC 8998 / GM/T 0024-2023 SM4-GCM AEAD**。
  - `crypto/sm2`：**GB/T 32918-2016** 全套实现——8×32-bit 有限域 Solinas 快速约简、恒定时间加法链求逆/开方、4-bit 固定窗口恒定时间标量乘，覆盖 **Part 2 签验（RFC 6979 确定性 nonce + DER）**、**Part 3 密钥交换（SM2-KE 含 S1/S2）**、**Part 4 公钥加解密（C1C3C2 与 ASN.1 DER `SM2Cipher`）**。
- **完整 SM9 标识密码套件（`sm9/`，GB/T 38635-2020 / GM/T 0044-2016）**：
  - `sm9/hash`：薄适配层，**100% 委托 `crypto/sm3` 与 `crypto/ct`**（零重复 SM3 压缩代码），提供 GB/T 38635.1 §5.4.2–5.4.3 `H1`/`H2`（恒定时间 320-bit 精确约简）、`KDF`、`MAC` 与 `Hv`。
  - `sm9/field` & `sm9/ec` & `sm9/pairing`：BN256 扩域塔（`U256`、`Fp`、`Fn`、`Fp2`、`Fp6`、`Fp12`）、恒定时间 `G1`/`G2` 标量乘、严格 `G2` 素数阶子群检测（拦截 wrong-twist 与 cofactor 攻击）以及最优 R-ate 双线性对（含双配对乘积优化 `pair_product`）。
  - `sm9/kgc`、`sm9/sign`、`sm9/keyex`、`sm9/enc`、`sm9` 门面：完整覆盖 KGC 签名/加密主密钥与用户私钥提取、**Part 2 数字签名**、**Part 3 密钥交换（含双向 S1/S2 确认）**、**Part 4 KEM 与 PKE（`KdfXor` 与直接调用共享 `crypto/sm4` 的 `Sm4EcbPkcs7`）**，通过全部国标附录 A 字节级测试向量及 IND-CCA2 / 畸形点对抗回归。
- **严格 ASN.1 DER 与国密 X.509 v3 双证书校验（`x509/der`、`x509`）**：
  - Strict DER 拒绝不定长、非最短长度编码、非规范布尔/整数等 BER 歧义攻击。
  - 支持国密 OID（`1.2.156.10197.1.301`、`1.2.156.10197.1.501`），强制校验 TLCP **签名证书 (`digitalSignature`) 与加密证书 (`keyEncipherment`/`keyAgreement`) 用途分离**、拒绝 CA 冒充叶子，并内置标准 X.509 v3 国密证书签发器。
- **防 Lucky13 记录层与 Sans-I/O TLCP 1.1 状态机（`record`、`handshake`、`state`、`web_api`）**：
  - 支持全部 4 大国标套件：`0xE013` `ECC_SM4_CBC_SM3`、`0xE053` `ECC_SM4_GCM_SM3`、`0xE011` `ECDHE_SM4_CBC_SM3`（SM2-KE + mTLCP）、`0xE051` `ECDHE_SM4_GCM_SM3`（SM2-KE + mTLCP）。
  - 记录层 CBC 解密路径采用**恒定时间填充检查 + 固定窗口 MAC 提取 + SM3 压缩块差值对齐**抵御 Padding Oracle / Lucky13 攻击；支持单向认证、双向 mTLCP、**Session ID 简短握手复用（1183B → 263B，节省 77%）**、16KB 自动分片与全路径 **Fail-Closed** Fatal Alert 终止。
  - 提供 `web_api/` 零依赖 JS ESM 导出包，同时驱动**浏览器零安装交互实验室**与 **Node.js 真实 OS TCP Socket 双向通信演示**；并在 `record/`、`handshake/` 及根门面导出无状态只读线格式解剖 API（`inspect_record` / `inspect_record_stream` / `inspect_handshake` / `inspect_alert`），供下游抓包与协议分析工具零耦合消费。

---

## 快速体验（一键运行）

### 1. 浏览器零安装交互实验室（在线或本地）
- 直接访问在线部署：<https://coolrfuldarkness.github.io/moontlcp/>
- 或本地编译 ESM 并在 Node 22 / 浏览器中运行：
```bash
moon build web_api --target js --release
node examples/web-demo/smoke.mjs
```

### 2. 原生 MoonBit 并发异步 TLCP 1.1 反向代理（`examples/tlcp_async_proxy/`）
```bash
cd examples/tlcp_async_proxy
moon update
moon test --target native -d          # Windows 下需先加载 VS MSVC vcvars64.bat
moon run --target native cmd/main
```
独立子模块（不向核心库引入任何外部依赖），基于 `moonbitlang/async/socket`（`TcpServer` / `Tcp`）与 `@async.with_task_group` 在真实 OS `127.0.0.1` 回路上完整演示：PEM 双证书加载与顺序防篡改、`ECC_SM4_GCM_SM3` 并发握手 + `SessionStore` Session ID 简短复用、`ECDHE_SM4_CBC_SM3` / `ECDHE_SM4_GCM_SM3` mTLCP 双向认证、加密 HTTP 请求向明文后端实时转发、>32KB 自动分片以及密文篡改（`BadRecordMac`）与 TLS 1.2 降级（`ProtocolVersion`）Fail-Closed 断连与优雅停机。

### 3. 真实 OS TCP Socket 端到端 TLCP 1.1 通信演示（Node.js 零 npm 依赖）
```bash
moon build web_api --target js --release
node examples/tlcp-tcp-demo/tlcp_tcp_demo.mjs
```
使用 Node.js 内置 `node:net` 在 `127.0.0.1` 真实 OS TCP 回路上分别跑通 **`ECC_SM4_GCM_SM3`** 与 **`ECDHE_SM4_CBC_SM3`（mTLCP 双向认证）** 完整双证书握手与双向加密报文传输。

### 4. 运行 6 阶段端到端 CLI 实景演示（TLCP 1.1 + SM9）
```bash
moon run --target wasm cmd/main
```
演示依次执行：
1. 国标基础密码向量自检（GB/T 32905 SM3、GB/T 32907 SM4、RFC 8998 SM4-GCM、GB/T 32918.2/3/4 SM2）；
2. 5 证书国密 PKI 生成、链校验与“签名/加密双证位置互换”即时拦截；
3. 全部 4 大 GM/T 0024 套件实景握手与双向密文传输；
4. Session ID 简短握手复用对比（1183B → 263B，节省 77%）；
5. TLCP 实时安全对抗演练（GCM Tag 翻转 → `BadRecordMac` + Fatal Alert；TLS 1.2 `0x0303` 降级 → `ProtocolVersion` + Fatal Alert）；
6. **GB/T 38635-2020 SM9 BN256 IBC 全流程实景演练**（基于共享 SM3/SM4/CT 核心：KGC 密钥派生 + 双线性对 + SM9 签验与篡改拦截 + KEM/PKE `KdfXor` & `Sm4EcbPkcs7` 加解密 + SM9 密钥交换双向确认）。

### 5. 运行全量三端测试（175/175 通过，0 警告）与外部消费端验证
```bash
moon test --target wasm -d
moon test --target js -d
moon test --target native -d   # Windows 下需先加载 VS MSVC vcvars64.bat
# 独立验证 mooncakes.io 已发布包消费（含 inspect_record / inspect_handshake 无状态解剖冒烟测试）：
cd examples/consumer && moon update && moon test --target wasm -d && moon test --target js -d
```

### 6. 运行 OpenSSL 3.5.6 ⇄ MoonTLCP 实时双向跨语言对拍
```bash
python harness/interop_openssl.py
```
使用本地真实 **OpenSSL 3.5.6** 完成 **8/8 双向字节级验证**：
- **MoonTLCP → OpenSSL 3.5.6（6/6 PASS）**：SM3 哈希、SM4-CBC-PKCS7、SM4-CTR、SM2 DER 签名验签（`distid:1234567812345678`）、SM2 ASN.1 `SM2Cipher` 解密、以及 MoonTLCP 签发的 Root CA / 签名证书 / 加密证书三张 X.509 v3 DER 证书经 `openssl x509` 规范重编码逐字节一致且密码学验签通过。
- **OpenSSL 3.5.6 → MoonTLCP（2/2 PASS）**：实时生成随机 SM3/SM4/SM2 向量与全新 OpenSSL SM2 双证书链，在 Wasm 与 JS 双端由 MoonTLCP 解析并验签 100% 通过。

### 7. 代码调用示例

#### TLCP 1.1 Sans-I/O 内存通道握手
```moonbit nocheck
let pki = @moontlcp.generate_test_pki(b"demo-seed")
let client_cfg = @state.ClientConfig::new([pki.ca_cert], b"client-seed")
let server_cfg = @state.ServerConfig::new(
  pki.server_sign_cert,
  pki.server_sign_priv,
  pki.server_enc_cert,
  pki.server_enc_priv,
  b"server-seed",
)
let client = @moontlcp.new_client(client_cfg)
let server = @moontlcp.new_server(server_cfg)
let (c_bytes, s_bytes) = @moontlcp.run_handshake_loop(client, server)

let wire = client.write_app_data(b"hello GM/T 0024 TLCP!")
let events = server.feed(wire[:])
```

#### SM9 BN256 标识签验与公钥加密（共享 SM3/SM4 核心）
```moonbit nocheck
let sign_master = @sm9.sign_master_from_seed(b"kgc-sign-seed")
let ds_alice = @sm9.extract_sign_key(sign_master, b"Alice").unwrap()
let sig = @sm9.sign(sign_master.public_key(), ds_alice, b"hello SM9").unwrap()
assert_true(@sm9.verify(sign_master.public_key(), b"Alice", b"hello SM9", sig))

let enc_master = @sm9.enc_master_from_seed(b"kgc-enc-seed")
let de_bob = @sm9.extract_enc_key(enc_master, b"Bob").unwrap()
let entropy = @moontlcp.sm3_hash(b"csprng-entropy-32b")
let ct = @sm9.encrypt(
  enc_master.public_key(),
  b"Bob",
  b"Chinese IBE standard",
  entropy,
  mode=@sm9_enc.EncMode::Sm4EcbPkcs7,
).unwrap()
let pt = @sm9.decrypt(b"Bob", de_bob, ct, mode=@sm9_enc.EncMode::Sm4EcbPkcs7).unwrap()
```

---

## 威胁模型与明确非目标（Threat Model & Non-Goals）

- **本库防御范围（In-Scope）**：主动网络攻击者（篡改、重放、乱序、TLS 1.2/TLCP 1.0 版本降级、双证书互换、CA 冒充叶子、64KiB/18KiB 帧 DoS、mTLCP 会话复用绕过）、远程时序/预言机攻击（CBC Lucky13 / Padding Oracle、SM9 IND-CCA2 密文探针、G2 wrong-twist/cofactor 攻击）与内存越界类漏洞。详见 [`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md)。
- **诚实边界与非目标（Non-Goals & Limitations）**：
  1. **JIT / Wasm / JS 恒定时间边界**：本库在源码与算法层通过 `crypto/ct` 无分支操作、固定窗口标量乘和 SM3 压缩块对齐消除逻辑侧信道，但 Wasm/JS JIT 编译器重排与底层 CPU 微架构侧信道（如 Flush+Reload / Spectre）无法由高级语言源码绝对免疫；对抗本地共置微架构攻击的高敏场景建议使用 Native 目标并在隔离安全域或 HSM/SDF 内运行。
  2. **调用方注入 CSPRNG 熵源**：核心库保持零 FFI 与确定性可测性，生产部署**必须**由宿主注入操作系统 CSPRNG 高熵 `seed` / `entropy`（SM9 强制 ≥32B）。
  3. **明确不包含**：DTLCP（UDP）、核心库内置异步 Socket 运行时绑定（核心库严格零外部依赖，原生异步代理参见独立子模块 `examples/tlcp_async_proxy/`，Node.js ESM 桥接参见 `examples/tlcp-tcp-demo/`）、PKCS#11/SKF/SDF 硬件驱动、在线 CRL/OCSP 与 OS 时钟读取、会话重协商及 ZUC 套件。

---

## 跨后端实测性能基准（`moon bench`）

以下为本机（Windows AMD64，MoonBit `0.1.20261119`，MSVC Build Tools 2022）**23 项统一基准**（14 项 TLCP + 9 项 SM9 BN256）实测结果（可通过 `moon bench --target wasm bench` / `moon bench --target native bench` 复现）：

| 基准项 | Wasm (`mean ± σ`) | Native MSVC (`mean ± σ`) |
| :--- | ---: | ---: |
| SM3 1KB | 36.69 µs ± 3.10 µs | **7.14 µs ± 80.51 ns** |
| SM3 16KB | 502.49 µs ± 4.34 µs | **103.63 µs ± 1.07 µs** |
| SM4-CBC encrypt 1KB | 14.91 µs ± 390.92 ns | **10.69 µs ± 111.26 ns** |
| SM4-CBC encrypt 16KB | 228.57 µs ± 11.28 µs | **165.00 µs ± 2.59 µs** |
| SM4-GCM encrypt 1KB | 29.95 µs ± 1.52 µs | **22.70 µs ± 1.75 µs** |
| SM4-GCM encrypt 16KB | 441.78 µs ± 23.88 µs | **331.49 µs ± 7.50 µs** |
| SM2 Sign DER | 3.25 ms ± 114.42 µs | **2.56 ms ± 44.37 µs** |
| SM2 Verify DER | 4.16 ms ± 57.96 µs | **3.29 ms ± 80.93 µs** |
| SM2 ASN.1 Encrypt 48B | 5.66 ms ± 70.69 µs | **4.55 ms ± 29.01 µs** |
| SM2 ASN.1 Decrypt 48B | 2.89 ms ± 69.20 µs | **2.30 ms ± 15.67 µs** |
| SM2 Key Exchange (GB/T 32918.3) | 4.75 ms ± 118.25 µs | **3.90 ms ± 121.03 µs** |
| X.509 SM2 Cert Parse + Verify | 4.50 ms ± 147.39 µs | **3.31 ms ± 21.46 µs** |
| RecordLayer SM4-CBC-SM3 `seal+open` 1KB | 141.37 µs ± 5.68 µs | **57.91 µs ± 7.46 µs** |
| RecordLayer SM4-GCM `seal+open` 1KB | 61.71 µs ± 2.59 µs | **58.45 µs ± 1.42 µs** |
| **SM9 BN256 R-ate Pairing `e(P2, P1)`** | **53.80 ms ± 6.65 ms** | 77.89 ms ± 2.72 ms |
| **SM9 G1 Scalar Mul** | **10.41 ms ± 813.34 µs** | 14.15 ms ± 350.05 µs |
| **SM9 G2 Scalar Mul** | **31.77 ms ± 1.65 ms** | 37.66 ms ± 360.12 µs |
| **SM9 Sign (GB/T 38635.2)** | **176.09 ms ± 4.54 ms** | 204.78 ms ± 4.00 ms |
| **SM9 Verify (GB/T 38635.2)** | **275.10 ms ± 53.68 ms** | 311.09 ms ± 18.00 ms |
| **SM9 Key Exchange Roundtrip (GB/T 38635.3)** | **533.47 ms ± 18.72 ms** | 711.25 ms ± 19.29 ms |
| **SM9 KEM Encap+Decap (GB/T 38635.4)** | **254.04 ms ± 7.21 ms** | 435.49 ms ± 34.56 ms |
| **SM9 PKE KDF-XOR Encrypt+Decrypt** | **228.59 ms ± 10.80 ms** | 396.53 ms ± 24.44 ms |
| **SM9 PKE SM4-ECB-PKCS#7 Encrypt+Decrypt** | **216.03 ms ± 5.41 ms** | 327.93 ms ± 29.45 ms |

---

## 仓库架构与文档导航

```text
moontlcp/
├── crypto/                     # 统一共享国密密码核心（Zero-FFI，零重复实现）
│   ├── ct/                     # 恒定时间防侧信道原语（TLCP + SM9 共用）
│   ├── sm3/                    # GB/T 32905 唯一 SM3 压缩内核 + HMAC-SM3 + TLCP-PRF + KDF
│   ├── sm4/                    # GB/T 32907 唯一 SM4 块核 + ECB-PKCS7 + CBC + CTR + RFC 8998 GCM
│   └── sm2/                    # GB/T 32918.2/3/4 SM2 曲线/签验/密钥交换/ASN.1 加解密
├── sm9/                        # GB/T 38635-2020 SM9 BN256 标识密码完整套件（复用 crypto/*）
│   ├── hash/                   # 薄适配层：委托 crypto/sm3 & crypto/ct，实现 H1/H2/KDF/MAC
│   ├── field/                  # BN256 有限域塔：U256, Fp, Fn, Fp2, Fp6, Fp12
│   ├── ec/                     # 恒定时间 G1/G2 群运算与 G2 素数阶子群校验
│   ├── pairing/                # BN256 最优 R-ate 双线性对（含双配对乘积）
│   ├── kgc/ · sign/ · keyex/ · enc/ · sm9.mbt
├── x509/                       # Strict ASN.1 DER + 国密 X.509 v3 证书签发与双证书用途分离校验
├── record/                     # GM/T 0024 记录层分片 + 防 Lucky13 CBC-SM3 + GCM AEAD
├── handshake/                  # GB/T 38636 全部 9 类握手消息编解码、Alert、Key Schedule、Transcript
├── state/                      # Sans-I/O ClientConn / ServerConn 状态机 + 26 项独立安全对抗测试
├── web_api/                    # 零依赖 JS ESM / Wasm / Native 交互实验与 TCP 桥接导出包
├── examples/
│   ├── tlcp_async_proxy/       # 独立 Native 并发异步 TLCP 1.1 反向代理（moonbitlang/async/socket）
│   ├── consumer/               # 独立 mooncakes.io 已发布包外部消费冒烟测试（含无状态线格式解剖）
│   ├── web-demo/               # 浏览器零安装交互实验室（index.html + Node smoke.mjs）
│   └── tlcp-tcp-demo/          # 真实 OS TCP Socket 端到端 TLCP 1.1 通信演示（Node.js 零 npm 依赖）
├── cmd/main/                   # 6 阶段一键可运行实景演示 CLI（TLCP 1.1 + SM9）
├── bench/                      # 23 项跨后端统一性能基准套件 (moon bench)
├── harness/                    # OpenSSL 3.5.6 ⇄ MoonTLCP 实时双向跨语言对拍 Harness
├── .github/workflows/          # 三端 CI（ci.yml）与 GitHub Pages 自动部署（pages.yml）
├── THIRD_PARTY_NOTICES.md      # 国标/RFC 向量溯源与外部参考合规声明
└── docs/
    ├── ARCHITECTURE.md         # 统一分层架构、TLCP + SM9 标准覆盖矩阵与共享原语去重说明
    ├── VERIFICATION_LOG.md     # 五层验证闭环、三端回归实测与研发抓虫实录
    ├── SECURITY_AUDIT.md       # P0/P1 安全审计缺陷修复清单与威胁模型
    ├── DEFENSE_QA.md           # 决赛评委白板硬核问答速查表
    └── ROADMAP.md              # 面向未来的演进路线图（v0.4.0 → v1.0.0+）
```

- 统一分层架构与国标条款覆盖矩阵：[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)
- 五层验证闭环与研发抓虫实录：[`docs/VERIFICATION_LOG.md`](docs/VERIFICATION_LOG.md)
- 安全审计与对抗加固报告：[`docs/SECURITY_AUDIT.md`](docs/SECURITY_AUDIT.md)
- 决赛评委白板问答速查表：[`docs/DEFENSE_QA.md`](docs/DEFENSE_QA.md)
- 前瞻开发路线图（`v0.4.0 → v1.0.0+`）：[`docs/ROADMAP.md`](docs/ROADMAP.md)
- 第三方合规与标准向量声明：[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)

---

## 开源协议

本项目采用 [Apache-2.0](LICENSE) 开源协议。
