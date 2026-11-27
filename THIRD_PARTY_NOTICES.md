# Third-Party Notices & Standard Vector Attributions

`CoolrfulDARkness/moontlcp` is licensed under the **Apache License 2.0** (see [`LICENSE`](LICENSE)).

## 1. Zero Third-Party Runtime Dependencies

`moontlcp` is a **100% pure MoonBit, zero-FFI** library with **zero external package dependencies** in [`moon.mod`](moon.mod). It depends solely on the MoonBit standard library (`moonbitlang/core`). No third-party source code, C libraries, or binaries are embedded or statically linked into the library.

---

## 2. National & International Standard Specifications and Test Vectors

All cryptographic primitives, wire formats, ASN.1 structures, and official test vectors in this repository were implemented from scratch directly from the following published technical standards:

| Standard | Title / Scope | Usage in `moontlcp` |
| :--- | :--- | :--- |
| **GB/T 32905-2016** | SM3 Cryptographic Hash Algorithm | `crypto/sm3` compression engine & Appendix A official test vectors (`"abc"`, 64-byte `"abcd"*16`) |
| **GB/T 32907-2016** | SM4 Block Cipher Algorithm | `crypto/sm4` S-box, key schedule, Appendix A single-block & 1,000,000-iteration test vectors |
| **GB/T 32918-2016 (Parts 1–5)** | SM2 Public Key Cryptographic Algorithm | `crypto/sm2` `sm2p256v1` domain parameters, default ID (`"1234567812345678"`), Part 2 Sign/Verify, Part 3 Key Exchange, Part 4 PKE & official vectors |
| **GM/T 0009-2023** | SM2 Cryptography Application Specification | ASN.1 DER `SM2Cipher` & `SM2Signature` encoding |
| **GM/T 0015-2023** | Digital Certificate Format Based on SM2 | `x509/` & `x509/der/` OIDs (`1.2.156.10197.1.301`, `1.2.156.10197.1.501`) and SM2 X.509 v3 profile |
| **GM/T 0024-2014 / GM/T 0024-2023 / GB/T 38636-2020** | SSL VPN / Transport Layer Cryptography Protocol (TLCP 1.1) | `record/`, `handshake/`, `state/`, `x509/dual_cert.mbt` — protocol version `0x0101`, dual-certificate KeyUsage separation, cipher suites `0xE011`/`0xE013`/`0xE051`/`0xE053`, `P_SM3` PRF, Alert codes, Session ID resumption |
| **GB/T 38635-2020 / GM/T 0044-2016 (Parts 1–5)** | SM9 Identity-Based Cryptographic Algorithms | `sm9/*` — BN256 curve & towering (`Fp → Fp2 → Fp6 → Fp12`), R-ate pairing, `H1`/`H2`/`KDF`/`MAC`, KGC extraction, Part 2 Sign, Part 3 KeyEx, Part 4 KEM & PKE (`KdfXor` / `Sm4EcbPkcs7`) and official Appendix A test vectors |
| **GM/T 0080-2020** | SM9 Cryptographic Algorithm Application Specification | Uncompressed `0x04` signature/point wire encodings |
| **IETF RFC 8998** | ShangMi (SM) Cipher Suites for TLS 1.3 | `crypto/sm4` SM4-GCM AEAD & Appendix A.1 official test vector |
| **IETF RFC 5288** | AES Galois Counter Mode (GCM) Cipher Suites for TLS | `record/record.mbt` 4B implicit salt + 8B explicit `seq_num` GCM nonce layout |
| **IETF RFC 2104** | HMAC: Keyed-Hashing for Message Authentication | `crypto/sm3` HMAC-SM3 |
| **IETF RFC 6979** | Deterministic Usage of DSA and ECDSA | `crypto/sm2` deterministic signing nonce derivation |
| **ITU-T X.690 & IETF RFC 5280** | ASN.1 Strict DER & X.509 v3 Certificate Profile | `x509/der/` Strict DER parser/encoder & `x509/` certificate chain verifier |

---

## 3. External Interoperability Tools & Reference Implementations (Not Bundled)

The following open-source projects were used strictly for external interoperability testing or public protocol specification cross-checking and are **not** bundled, vendored, or linked into `moontlcp`:

1. **OpenSSL 3.5.6**
   - **License**: Apache License 2.0 (<https://www.openssl.org/source/license.html>)
   - **Relationship**: Invoked externally as a subprocess exclusively by the developer/CI test script [`harness/interop_openssl.py`](harness/interop_openssl.py) to perform live 8/8 bidirectional byte-level verification of SM3, SM4-CBC, SM4-CTR, SM2 DER signatures, SM2 ASN.1 `SM2Cipher`, and X.509 v3 SM2 dual-certificate chains. No OpenSSL source code or binaries are included in this repository.

2. **gotlcp (`gitee.com/Trisia/gotlcp`)**
   - **License**: Apache License 2.0
   - **Relationship**: Consulted purely as an open-source reference when cross-checking GM/T 0024-2014 / GB/T 38636-2020 wire-format ambiguities (such as static `ECC_SM4_*` `ServerKeyExchange` framing and cipher suite wire IDs). Zero code was copied, ported, or translated from `gotlcp`.
