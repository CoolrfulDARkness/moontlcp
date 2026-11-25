# moontlcp

**纯 MoonBit、零 C/FFI 依赖、类型安全、Sans-I/O 架构的国密双证书传输层密码协议栈（TLCP 1.1 / `0x0101`，遵循 GM/T 0024-2014 & GB/T 38636-2020）**

> MoonBit 生态首个完整覆盖 **SM2（签验 / 密钥交换 / ASN.1 加解密）+ SM3 / HMAC / TLCP-PRF + SM4-CBC / CTR / GCM + Strict ASN.1 DER + 国密 X.509 v3 双证书链校验 + TLCP 1.1 全部 4 大国标套件与 mTLCP / 会话复用** 的传输层安全协议实现。一套核心代码原生运行于 **WebAssembly (Wasm) / JavaScript (JS) / Native** 三端。

---

## 核心特性

- **零外部依赖、零 FFI、零 `unsafe`**：所有密码原语与协议状态机 100% 由纯 MoonBit 实现，天然杜绝 C/C++ 缓冲区溢出与 Heartbleed 类内存越界风险。
- **全套国密密码基座（带恒定时间侧信道防护）**：
  - `crypto/ct`：恒定时间比较、选择与零化原语。
  - `crypto/sm3`：**GB/T 32905-2016** 流式/单次 SM3、RFC 2104 HMAC-SM3、GM/T 0024 `P_SM3` PRF、GB/T 32918.4 KDF。
  - `crypto/sm4`：**GB/T 32907-2016** SM4 分组加密、恒定时间 PKCS#7 CBC、CTR、以及 **RFC 8998 / GM/T 0024-2023 SM4-GCM AEAD**。
  - `crypto/sm2`：**GB/T 32918-2016** 全套实现——8×32-bit 有限域 Solinas 快速约简、恒定时间加法链求逆/开方、4-bit 固定窗口恒定时间标量乘，完整覆盖 **Part 2 签名验签（含 RFC 6979 确定性 nonce 与 DER）**、**Part 3 密钥交换（SM2-KE 含 S1/S2）**、**Part 4 公钥加解密（C1C3C2 与 ASN.1 DER `SM2Cipher`）**。
- **严格 ASN.1 DER 与国密 X.509 v3 双证书校验（`x509/der`、`x509`）**：
  - Strict DER 拒绝不定长、非最短长度编码、非规范布尔/整数等 BER 歧义攻击。
  - 支持国密 OID（`1.2.156.10197.1.301`、`1.2.156.10197.1.501`），强制校验 TLCP **签名证书 (`digitalSignature`) 与加密证书 (`keyEncipherment`/`keyAgreement`) 用途分离**，并内置标准 X.509 v3 国密证书签发器。
- **防 Lucky13 记录层与 Sans-I/O 类型状态机（`record`、`handshake`、`state`）**：
  - 支持全部 4 大国标套件：
    - `0xE013` `ECC_SM4_CBC_SM3`
    - `0xE053` `ECC_SM4_GCM_SM3`
    - `0xE011` `ECDHE_SM4_CBC_SM3`（SM2-KE 前向安全 + mTLCP 双证书互验）
    - `0xE051` `ECDHE_SM4_GCM_SM3`（SM2-KE 前向安全 + mTLCP 双证书互验）
  - 记录层 CBC 解密路径采用**恒定时间填充检查 + 固定窗口 MAC 提取 + SM3 压缩块差值对齐**抵御 Padding Oracle / Lucky13 攻击；所有错误统一返回 `BadRecordMac`。
  - 支持单向认证、双向认证（mTLCP）、**Session ID 简短握手复用（实测握手字节数由 1183B 降至 263B，节省 77%）**、16KB 自动分片与全路径 **Fail-Closed** Fatal Alert 终止。

---

## 快速体验（一键运行）

### 1. 运行 5 阶段端到端 CLI 实景演示
```bash
moon run cmd/main
```
演示依次执行：
1. 国标测试向量自检（GB/T 32905 SM3、GB/T 32907 SM4、RFC 8998 SM4-GCM、GB/T 32918.2/3/4 SM2）；
2. 5 证书国密 PKI 生成、链校验与“签名/加密双证位置互换”即时拦截；
3. 全部 4 大 GM/T 0024 套件实景握手与双向密文传输；
4. Session ID 简短握手复用对比（1183B → 263B，节省 77%）；
5. 实时安全对抗演练（GCM Tag 翻转 → `BadRecordMac` + Fatal Alert；TLS 1.2 `0x0303` 降级 → `ProtocolVersion` + Fatal Alert）。

### 2. 运行全量三端测试（0 警告）
```bash
moon test --target wasm -d
moon test --target js -d
moon test --target native -d   # Windows 下需先加载 VS MSVC vcvars64.bat
```

### 3. 运行 OpenSSL 3.5.6 ⇄ MoonTLCP 实时双向跨语言对拍
```bash
python harness/interop_openssl.py
```
使用本地真实 **OpenSSL 3.5.6** 完成 **8/8 双向字节级验证**：
- **MoonTLCP → OpenSSL 3.5.6（6/6 PASS）**：SM3 哈希、SM4-CBC-PKCS7、SM4-CTR、SM2 DER 签名验签（`distid:1234567812345678`）、SM2 ASN.1 `SM2Cipher` 解密、以及 MoonTLCP 签发的 Root CA / 签名证书 / 加密证书三张 X.509 v3 DER 证书经 `openssl x509` 规范重编码逐字节一致且密码学验签通过。
- **OpenSSL 3.5.6 → MoonTLCP（2/2 PASS）**：实时生成随机 SM3/SM4/SM2 向量与全新 OpenSSL SM2 双证书链，在 Wasm 与 JS 双端由 MoonTLCP 解析并验签 100% 通过。

### 4. 代码调用示例（Sans-I/O 内存通道握手）
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

---

## 三端实测性能基准（`moon bench`）

以下为本机（Windows AMD64，MoonBit `v0.10.22`，MSVC `14.44`）14 项基准实测结果（可通过 `moon bench bench` 复现）：

| 基准项 | Wasm (`mean ± σ`) | JS (`mean ± σ`) | Native MSVC (`mean ± σ`) |
| :--- | ---: | ---: | ---: |
| SM3 1KB | 53.17 µs ± 1.66 µs | 21.81 µs ± 2.09 µs | **8.49 µs ± 340 ns** |
| SM3 16KB | 750.20 µs (~21.8 MB/s) | 287.47 µs (~57.0 MB/s) | **116.81 µs (~140.3 MB/s)** |
| SM4-CBC encrypt 1KB | 21.41 µs ± 834 ns | 23.49 µs ± 1.20 µs | **13.32 µs ± 264 ns** |
| SM4-CBC encrypt 16KB | 340.09 µs (~48.2 MB/s) | 378.13 µs (~43.3 MB/s) | **197.71 µs (~82.9 MB/s)** |
| SM4-GCM encrypt 1KB | 38.30 µs ± 2.32 µs | 1.24 ms ± 102.77 µs | **25.98 µs ± 466 ns** |
| SM4-GCM encrypt 16KB | 693.56 µs (~23.6 MB/s) | 19.50 ms ± 2.51 ms | **398.62 µs (~41.1 MB/s)** |
| SM2 Sign DER | 5.65 ms ± 531 µs | 27.24 ms ± 1.10 ms | **3.07 ms ± 193 µs** |
| SM2 Verify DER | 7.15 ms ± 634 µs | 35.62 ms ± 435 µs | **3.81 ms ± 116 µs** |
| SM2 ASN.1 Encrypt 48B | 6.50 ms ± 448 µs | 49.08 ms ± 1.80 ms | **5.46 ms ± 114 µs** |
| SM2 ASN.1 Decrypt 48B | 3.00 ms ± 133 µs | 23.71 ms ± 840 µs | **2.50 ms ± 48 µs** |
| SM2 Key Exchange (GB/T 32918.3) | 5.18 ms ± 228 µs | 39.69 ms ± 2.26 ms | **4.18 ms ± 36 µs** |
| X.509 SM2 Cert Parse + Verify | 4.58 ms ± 274 µs | 38.04 ms ± 1.89 ms | **3.72 ms ± 132 µs** |
| RecordLayer SM4-CBC-SM3 `seal+open` 1KB | 134.85 µs ± 2.17 µs | 151.97 µs ± 5.12 µs | **57.71 µs ± 2.24 µs** |
| RecordLayer SM4-GCM `seal+open` 1KB | 68.10 µs ± 4.17 µs | 2.27 ms ± 112 µs | **50.54 µs ± 1.70 µs** |

---

## 仓库架构与文档导航

```text
moontlcp/
├── crypto/
│   ├── ct/          # 恒定时间防侧信道原语
│   ├── sm3/         # GB/T 32905 SM3 + HMAC-SM3 + TLCP-PRF + KDF
│   ├── sm4/         # GB/T 32907 SM4 + CBC + CTR + RFC 8998 GCM AEAD
│   └── sm2/         # GB/T 32918.2/3/4 SM2 曲线/签验/密钥交换/ASN.1 加解密
├── x509/
│   ├── der/         # 零依赖 Strict ASN.1 DER + PEM + 国密 OID
│   └── ...          # 国密 X.509 v3 证书解析、签发与 TLCP 双证书用途分离校验
├── record/          # GM/T 0024 记录层分片 + 防 Lucky13 CBC-SM3 + GCM AEAD
├── handshake/       # GB/T 38636 全部 9 类握手消息编解码、Alert、Key Schedule、Transcript
├── state/           # Sans-I/O ClientConn / ServerConn 状态机 + 22 项独立安全对抗测试
├── cmd/main/        # 5 阶段一键可运行实景演示 CLI
├── bench/           # 14 项三端性能基准套件 (moon bench)
├── harness/         # OpenSSL 3.5.6 ⇄ MoonTLCP 实时双向跨语言对拍 Harness
└── docs/
    ├── ARCHITECTURE.md      # 分层架构、GM/T 0024 逐条款覆盖矩阵与范围边界说明
    └── VERIFICATION_LOG.md  # 五层验证闭环与研发期真实抓虫/防错实录
```

- 详细架构设计、GM/T 0024 逐条款覆盖矩阵与非目标边界说明：见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。
- 完整五层验证闭环、OpenSSL 3.5.6 兼容性发现与研发抓虫实录：见 [`docs/VERIFICATION_LOG.md`](docs/VERIFICATION_LOG.md)。

---

## 开源协议

本项目采用 [Apache-2.0](LICENSE) 开源协议。
