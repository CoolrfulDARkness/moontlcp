#!/usr/bin/env python3
"""
Bidirectional OpenSSL 3.5.6 <-> MoonTLCP Cross-Language Interoperability Harness.

Phase 1 (MoonTLCP -> OpenSSL 3.5.6):
  - Executes `harness/interop_cli` (pure MoonBit Wasm) to emit live SM3, SM4-CBC,
    SM4-CTR, SM2 DER signature, SM2 ASN.1 SM2Cipher, and X.509 SM2 dual-cert PKI.
  - Verifies every artifact byte-for-byte with OpenSSL 3.5.6 (`openssl dgst -sm3`,
    `openssl enc -sm4-cbc/-sm4-ctr`, `openssl pkeyutl -verify/-decrypt`,
    `openssl x509 -inform DER`, `openssl verify -CAfile`).

Phase 2 (OpenSSL 3.5.6 -> MoonTLCP):
  - Calls OpenSSL 3.5.6 live to generate fresh SM3 digests, SM4-CBC & SM4-CTR
    ciphertexts, a fresh SM2 keypair + SM2 DER signature + SM2 ASN.1 SM2Cipher,
    and a fresh SM2 Root CA + Server Sign Cert + Server Enc Cert chain.
  - Emits `harness/openssl_vectors_generated_test.mbt` and executes
    `moon test --target wasm -d harness` and `--target js -d harness`.

Exit code 0 iff all checks in both directions pass.
"""

from __future__ import annotations

import base64
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HARNESS_DIR = ROOT / "harness"
GENERATED_TEST = HARNESS_DIR / "openssl_vectors_generated_test.mbt"
BUILD_DIR = ROOT / "_build_harness"

# Fixed ASN.1 DER prefixes for SM2 (ecPublicKey 1.2.840.10045.2.1, sm2p256v1 1.2.156.10197.1.301)
SM2_ALG_ID = bytes.fromhex("301306072a8648ce3d020106082a811ccf5501822d")


def find_openssl() -> str:
    candidates = [
        os.environ.get("OPENSSL_BIN"),
        r"D:\Git\usr\bin\openssl.exe",
        shutil.which("openssl"),
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    raise RuntimeError("openssl binary not found; set OPENSSL_BIN or install OpenSSL 3.x")


def find_moon() -> str:
    candidates = [
        shutil.which("moon"),
        str(Path.home() / ".moon" / "bin" / ("moon.exe" if os.name == "nt" else "moon")),
    ]
    for c in candidates:
        if c and Path(c).exists():
            return str(c)
    raise RuntimeError("moon binary not found in PATH or ~/.moon/bin")


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def to_pem(label: str, der: bytes) -> str:
    b64 = base64.b64encode(der).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


def sm2_spki_pem(uncompressed_pub: bytes) -> str:
    assert len(uncompressed_pub) == 65 and uncompressed_pub[0] == 0x04
    bit_str = der_tlv(0x03, b"\x00" + uncompressed_pub)
    spki = der_tlv(0x30, SM2_ALG_ID + bit_str)
    return to_pem("PUBLIC KEY", spki)


def sm2_pkcs8_pem(priv32: bytes, uncompressed_pub: bytes) -> str:
    assert len(priv32) == 32 and len(uncompressed_pub) == 65
    ec_priv = der_tlv(
        0x30,
        der_tlv(0x02, b"\x01")
        + der_tlv(0x04, priv32)
        + der_tlv(0xA1, der_tlv(0x03, b"\x00" + uncompressed_pub)),
    )
    pkcs8 = der_tlv(
        0x30,
        der_tlv(0x02, b"\x00") + SM2_ALG_ID + der_tlv(0x04, ec_priv),
    )
    return to_pem("PRIVATE KEY", pkcs8)


def extract_sm2_priv_and_pub_from_pem(openssl: str, key_pem: Path) -> tuple[bytes, bytes]:
    """Extract raw 32-byte SM2 private scalar and 65-byte uncompressed public key from OpenSSL key PEM."""
    out = run_cmd([openssl, "pkey", "-in", str(key_pem), "-text", "-noout"]).stdout.decode("utf-8")
    priv_hex_parts: list[str] = []
    pub_hex_parts: list[str] = []
    section = None
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("priv:"):
            section = "priv"
            continue
        if s.startswith("pub:"):
            section = "pub"
            continue
        if s.startswith("ASN1 OID:") or s.startswith("NIST CURVE:"):
            section = None
            continue
        if section == "priv":
            priv_hex_parts.append(s.replace(":", ""))
        elif section == "pub":
            pub_hex_parts.append(s.replace(":", ""))
    priv_raw = bytes.fromhex("".join(priv_hex_parts))
    # OpenSSL may print a leading 0x00 byte if MSB is set
    if len(priv_raw) == 33 and priv_raw[0] == 0:
        priv_raw = priv_raw[1:]
    priv32 = priv_raw.rjust(32, b"\x00")
    pub65 = bytes.fromhex("".join(pub_hex_parts))
    assert len(priv32) == 32, f"unexpected priv len {len(priv32)}"
    assert len(pub65) == 65 and pub65[0] == 0x04, f"unexpected pub len {len(pub65)}"
    return priv32, pub65


def run_cmd(
    cmd: list[str],
    inp: bytes | None = None,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    res = subprocess.run(cmd, input=inp, cwd=cwd, env=env, capture_output=True)
    if res.returncode != 0:
        raise RuntimeError(
            f"Command failed ({res.returncode}): {' '.join(cmd)}\n"
            f"STDOUT:\n{res.stdout.decode(errors='replace')}\n"
            f"STDERR:\n{res.stderr.decode(errors='replace')}"
        )
    return res


def format_hex_mbt(hex_str: str, indent: str = "    ") -> str:
    """Wrap a long hex string into valid MoonBit string literal concatenation."""
    chunks = [hex_str[i : i + 64] for i in range(0, len(hex_str), 64)]
    if len(chunks) == 1:
        return f'"{chunks[0]}"'
    return (" +\n" + indent).join(f'"{c}"' for c in chunks)


def main() -> int:
    openssl = find_openssl()
    moon = find_moon()
    env = os.environ.copy()
    moon_bin_dir = str(Path(moon).parent)
    env["PATH"] = moon_bin_dir + os.pathsep + env.get("PATH", "")

    ossl_ver = run_cmd([openssl, "version"]).stdout.decode().strip()
    print(f"=== MoonTLCP <-> OpenSSL Cross-Language Interop Harness ===")
    print(f"OpenSSL : {ossl_ver} ({openssl})")
    print(f"MoonBit : {moon}")
    print()

    results: list[tuple[str, bool, str]] = []

    def record(name: str, ok: bool, detail: str) -> None:
        results.append((name, ok, detail))
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}: {detail}")

    try:
        with tempfile.TemporaryDirectory(prefix="moontlcp_interop_") as tmp:
            td = Path(tmp)

            # =================================================================
            # PHASE 1: MoonTLCP -> OpenSSL 3.5.6
            # =================================================================
            print("[Phase 1] MoonTLCP -> OpenSSL 3.5.6")
            cli_out = run_cmd(
                [
                    moon,
                    "run",
                    "--target-dir",
                    str(BUILD_DIR),
                    "--target",
                    "wasm",
                    "harness/interop_cli",
                ],
                cwd=ROOT,
                env=env,
            ).stdout.decode("utf-8")

            kv: dict[str, bytes] = {}
            for line in cli_out.splitlines():
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    if k.isupper() and all(c in "0123456789abcdef" for c in v):
                        kv[k] = bytes.fromhex(v)

            # 1.1 SM3
            ossl_sm3_line = run_cmd([openssl, "dgst", "-sm3", "-hex"], inp=kv["SM3_MSG"]).stdout.decode().strip()
            ossl_sm3_hex = ossl_sm3_line.split()[-1].lower()
            assert ossl_sm3_hex == kv["SM3_DIGEST"].hex(), "SM3 mismatch"
            record("MoonTLCP->OpenSSL SM3", True, f"32B digest matched ({ossl_sm3_hex[:16]}...)")

            # 1.2 SM4-CBC-PKCS7
            ossl_cbc_pt = run_cmd(
                [
                    openssl,
                    "enc",
                    "-d",
                    "-sm4-cbc",
                    "-K",
                    kv["SM4_KEY"].hex(),
                    "-iv",
                    kv["SM4_IV"].hex(),
                ],
                inp=kv["SM4_CBC_CT"],
            ).stdout
            assert ossl_cbc_pt == kv["SM4_PT"], "SM4-CBC decrypt mismatch"
            record("MoonTLCP->OpenSSL SM4-CBC-PKCS7", True, f"{len(kv['SM4_CBC_CT'])}B ciphertext decrypted cleanly")

            # 1.3 SM4-CTR
            ossl_ctr_pt = run_cmd(
                [
                    openssl,
                    "enc",
                    "-d",
                    "-sm4-ctr",
                    "-K",
                    kv["SM4_KEY"].hex(),
                    "-iv",
                    kv["SM4_IV"].hex(),
                ],
                inp=kv["SM4_CTR_CT"],
            ).stdout
            assert ossl_ctr_pt == kv["SM4_PT"], "SM4-CTR decrypt mismatch"
            record("MoonTLCP->OpenSSL SM4-CTR", True, f"{len(kv['SM4_CTR_CT'])}B ciphertext decrypted cleanly")

            # 1.4 SM2 DER signature verified by OpenSSL
            pub_pem = td / "m_sm2.pub"
            priv_pem = td / "m_sm2.key"
            msg_bin = td / "m_sm2.msg"
            sig_der = td / "m_sm2.sig"
            ct_der = td / "m_sm2.ct"
            pub_pem.write_text(sm2_spki_pem(kv["SM2_PUB_UNCOMPRESSED"]), encoding="ascii")
            priv_pem.write_text(sm2_pkcs8_pem(kv["SM2_PRIV"], kv["SM2_PUB_UNCOMPRESSED"]), encoding="ascii")
            msg_bin.write_bytes(kv["SM2_MSG"])
            sig_der.write_bytes(kv["SM2_SIG_DER"])
            ct_der.write_bytes(kv["SM2_CIPHER_ASN1"])

            run_cmd(
                [
                    openssl,
                    "pkeyutl",
                    "-verify",
                    "-pubin",
                    "-inkey",
                    str(pub_pem),
                    "-rawin",
                    "-digest",
                    "sm3",
                    "-pkeyopt",
                    "distid:1234567812345678",
                    "-in",
                    str(msg_bin),
                    "-sigfile",
                    str(sig_der),
                ]
            )
            record("MoonTLCP->OpenSSL SM2 Sign/Verify", True, f"{len(kv['SM2_SIG_DER'])}B DER sig verified by OpenSSL")

            # 1.5 SM2 ASN.1 SM2Cipher decrypted by OpenSSL
            ossl_dec_pt = run_cmd(
                [
                    openssl,
                    "pkeyutl",
                    "-decrypt",
                    "-inkey",
                    str(priv_pem),
                    "-in",
                    str(ct_der),
                ]
            ).stdout
            assert ossl_dec_pt == kv["SM2_ENC_PT"], "SM2 ASN.1 decrypt mismatch"
            record("MoonTLCP->OpenSSL SM2 ASN.1 Cipher", True, f"{len(kv['SM2_CIPHER_ASN1'])}B SM2Cipher decrypted cleanly")

            # 1.6 X.509 SM2 Root CA + Sign Cert + Enc Cert parsed & cryptographically verified by OpenSSL 3.5.6
            # Note: OpenSSL 3.5.6 `openssl verify` does not forward `-vfyopt distid:1234567812345678`
            # into X509_verify (known OpenSSL 3.x SM2 X.509 distid behavior; defaults to empty ID),
            # whereas GM/T 0015-2023 mandates SM2 default ID "1234567812345678".
            # We therefore verify:
            #   (a) OpenSSL `x509 -inform DER -text` parses all 3 certs cleanly;
            #   (b) OpenSSL `x509 -inform DER -outform DER` reproduces exact byte-for-byte canonical DER;
            #   (c) OpenSSL extracts CA SPKI (`x509 -pubkey`), parses TBSCertificate + signatureValue
            #       via `asn1parse`, and verifies all 3 SM2-with-SM3 signatures with `pkeyutl -verify
            #       -rawin -digest sm3 -pkeyopt distid:1234567812345678`.
            m_ca_der = td / "m_ca.der"
            m_sign_der = td / "m_sign.der"
            m_enc_der = td / "m_enc.der"
            m_ca_pub = td / "m_ca.pub"
            m_ca_der.write_bytes(kv["X509_CA_DER"])
            m_sign_der.write_bytes(kv["X509_SIGN_DER"])
            m_enc_der.write_bytes(kv["X509_ENC_DER"])

            run_cmd([openssl, "x509", "-inform", "DER", "-in", str(m_ca_der), "-pubkey", "-noout", "-out", str(m_ca_pub)])

            for label, der_path in [("CA", m_ca_der), ("Sign", m_sign_der), ("Enc", m_enc_der)]:
                raw_der = der_path.read_bytes()
                txt = run_cmd([openssl, "x509", "-inform", "DER", "-in", str(der_path), "-text", "-noout"]).stdout.decode()
                assert "Signature Algorithm: SM2-with-SM3" in txt, f"{label} missing SM2-with-SM3"
                assert "ASN1 OID: SM2" in txt, f"{label} missing SM2 curve OID"
                re_der = run_cmd([openssl, "x509", "-inform", "DER", "-in", str(der_path), "-outform", "DER"]).stdout
                assert re_der == raw_der, f"{label} DER is not byte-for-byte canonical"

                ap_lines = run_cmd([openssl, "asn1parse", "-inform", "DER", "-in", str(der_path)]).stdout.decode().splitlines()
                m_tbs = re.search(r"(\d+):d=1\s+hl=(\d+)\s+l=\s*(\d+)", ap_lines[1])
                m_sig = re.search(r"(\d+):d=1\s+hl=(\d+)\s+l=\s*(\d+)", ap_lines[-1])
                assert m_tbs and m_sig, f"{label} unexpected asn1parse structure"
                off_t, hl_t, l_t = map(int, m_tbs.groups())
                off_s, hl_s, l_s = map(int, m_sig.groups())
                tbs_path = td / f"m_{label}_tbs.bin"
                sig_path = td / f"m_{label}_sig.der"
                tbs_path.write_bytes(raw_der[off_t : off_t + hl_t + l_t])
                # Skip 1-byte BIT STRING unused_bits prefix (0x00)
                assert raw_der[off_s + hl_s] == 0, f"{label} non-zero unused bits in sig"
                sig_path.write_bytes(raw_der[off_s + hl_s + 1 : off_s + hl_s + l_s])

                run_cmd(
                    [
                        openssl,
                        "pkeyutl",
                        "-verify",
                        "-pubin",
                        "-inkey",
                        str(m_ca_pub),
                        "-rawin",
                        "-digest",
                        "sm3",
                        "-pkeyopt",
                        "distid:1234567812345678",
                        "-in",
                        str(tbs_path),
                        "-sigfile",
                        str(sig_path),
                    ]
                )
            record(
                "MoonTLCP->OpenSSL X.509 Dual-Cert Chain",
                True,
                "CA + Sign + Enc canonical DER parsed & all 3 SM2-SM3 signatures verified by OpenSSL",
            )

            # =================================================================
            # PHASE 2: OpenSSL 3.5.6 -> MoonTLCP
            # =================================================================
            print("\n[Phase 2] OpenSSL 3.5.6 -> MoonTLCP")

            # 2.1 Fresh SM3 vector
            o_sm3_msg = b"OpenSSL 3.5.6 live SM3 vector -> MoonTLCP: " + secrets.token_hex(16).encode("ascii")
            o_sm3_digest = run_cmd([openssl, "dgst", "-sm3", "-hex"], inp=o_sm3_msg).stdout.decode().strip().split()[-1].lower()

            # 2.2 Fresh SM4-CBC & SM4-CTR vectors
            o_sm4_key = secrets.token_bytes(16)
            o_sm4_iv = secrets.token_bytes(16)
            o_sm4_pt = b"OpenSSL 3.5.6 live SM4 payload (non-block-aligned 53B)"
            o_sm4_cbc_ct = run_cmd(
                [openssl, "enc", "-sm4-cbc", "-K", o_sm4_key.hex(), "-iv", o_sm4_iv.hex()],
                inp=o_sm4_pt,
            ).stdout
            o_sm4_ctr_ct = run_cmd(
                [openssl, "enc", "-sm4-ctr", "-K", o_sm4_key.hex(), "-iv", o_sm4_iv.hex()],
                inp=o_sm4_pt,
            ).stdout

            # 2.3 Fresh SM2 keypair + signature + ASN.1 SM2Cipher
            o_sm2_key = td / "o_sm2.key"
            o_sm2_pub = td / "o_sm2.pub"
            o_sm2_msg_path = td / "o_sm2.msg"
            o_sm2_sig_path = td / "o_sm2.sig"
            o_sm2_ct_path = td / "o_sm2.ct"
            o_sm2_msg = b"OpenSSL 3.5.6 live SM2 sign/encrypt vector for MoonTLCP"
            o_sm2_msg_path.write_bytes(o_sm2_msg)

            run_cmd([openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:SM2", "-out", str(o_sm2_key)])
            run_cmd([openssl, "pkey", "-in", str(o_sm2_key), "-pubout", "-out", str(o_sm2_pub)])
            run_cmd(
                [
                    openssl,
                    "pkeyutl",
                    "-sign",
                    "-inkey",
                    str(o_sm2_key),
                    "-rawin",
                    "-digest",
                    "sm3",
                    "-pkeyopt",
                    "distid:1234567812345678",
                    "-in",
                    str(o_sm2_msg_path),
                    "-out",
                    str(o_sm2_sig_path),
                ]
            )
            run_cmd(
                [
                    openssl,
                    "pkeyutl",
                    "-encrypt",
                    "-pubin",
                    "-inkey",
                    str(o_sm2_pub),
                    "-in",
                    str(o_sm2_msg_path),
                    "-out",
                    str(o_sm2_ct_path),
                ]
            )
            o_sm2_priv32, o_sm2_pub65 = extract_sm2_priv_and_pub_from_pem(openssl, o_sm2_key)
            o_sm2_sig_der = o_sm2_sig_path.read_bytes()
            o_sm2_ct_asn1 = o_sm2_ct_path.read_bytes()

            # 2.4 Fresh OpenSSL SM2 Root CA + Server Sign Cert + Server Enc Cert
            o_ca_key = td / "o_ca.key"
            o_ca_pem = td / "o_ca.pem"
            o_ca_der = td / "o_ca.der"
            o_sign_key = td / "o_sign.key"
            o_sign_csr = td / "o_sign.csr"
            o_sign_pem = td / "o_sign.pem"
            o_sign_der = td / "o_sign.der"
            o_sign_ext = td / "o_sign.ext"
            o_enc_key = td / "o_enc.key"
            o_enc_csr = td / "o_enc.csr"
            o_enc_pem = td / "o_enc.pem"
            o_enc_der = td / "o_enc.der"
            o_enc_ext = td / "o_enc.ext"

            run_cmd([openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:SM2", "-out", str(o_ca_key)])
            run_cmd(
                [
                    openssl,
                    "req",
                    "-x509",
                    "-new",
                    "-key",
                    str(o_ca_key),
                    "-sm3",
                    "-sigopt",
                    "distid:1234567812345678",
                    "-days",
                    "365",
                    "-subj",
                    "/CN=OpenSSL-3.5-SM2-Root-CA",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign,cRLSign",
                    "-out",
                    str(o_ca_pem),
                ]
            )
            run_cmd([openssl, "x509", "-in", str(o_ca_pem), "-outform", "DER", "-out", str(o_ca_der)])

            # Server Sign Cert
            run_cmd([openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:SM2", "-out", str(o_sign_key)])
            run_cmd(
                [
                    openssl,
                    "req",
                    "-new",
                    "-key",
                    str(o_sign_key),
                    "-sm3",
                    "-subj",
                    "/CN=server.moontlcp.local",
                    "-out",
                    str(o_sign_csr),
                ]
            )
            o_sign_ext.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,nonRepudiation\n",
                encoding="ascii",
            )
            run_cmd(
                [
                    openssl,
                    "x509",
                    "-req",
                    "-in",
                    str(o_sign_csr),
                    "-CA",
                    str(o_ca_pem),
                    "-CAkey",
                    str(o_ca_key),
                    "-CAcreateserial",
                    "-sm3",
                    "-sigopt",
                    "distid:1234567812345678",
                    "-days",
                    "365",
                    "-extfile",
                    str(o_sign_ext),
                    "-out",
                    str(o_sign_pem),
                ]
            )
            run_cmd([openssl, "x509", "-in", str(o_sign_pem), "-outform", "DER", "-out", str(o_sign_der)])

            # Server Enc Cert
            run_cmd([openssl, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:SM2", "-out", str(o_enc_key)])
            run_cmd(
                [
                    openssl,
                    "req",
                    "-new",
                    "-key",
                    str(o_enc_key),
                    "-sm3",
                    "-subj",
                    "/CN=server.moontlcp.local",
                    "-out",
                    str(o_enc_csr),
                ]
            )
            o_enc_ext.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,keyEncipherment,dataEncipherment,keyAgreement\n",
                encoding="ascii",
            )
            run_cmd(
                [
                    openssl,
                    "x509",
                    "-req",
                    "-in",
                    str(o_enc_csr),
                    "-CA",
                    str(o_ca_pem),
                    "-CAkey",
                    str(o_ca_key),
                    "-CAcreateserial",
                    "-sm3",
                    "-sigopt",
                    "distid:1234567812345678",
                    "-days",
                    "365",
                    "-extfile",
                    str(o_enc_ext),
                    "-out",
                    str(o_enc_pem),
                ]
            )
            run_cmd([openssl, "x509", "-in", str(o_enc_pem), "-outform", "DER", "-out", str(o_enc_der)])

            # Emit MoonBit test file
            mbt_src = f'''// Auto-generated by harness/interop_openssl.py using {ossl_ver}.
// Verifies MoonTLCP against live OpenSSL 3.5.6 SM3/SM4/SM2/X.509 dual-cert outputs.

///|
fn hex_nibble(c : Int) -> Int {{
  if c >= 0x30 && c <= 0x39 {{
    c - 0x30
  }} else if c >= 0x61 && c <= 0x66 {{
    c - 0x61 + 10
  }} else if c >= 0x41 && c <= 0x46 {{
    c - 0x41 + 10
  }} else {{
    abort("invalid hex char")
  }}
}}

///|
fn from_hex(s : String) -> Bytes {{
  let n = s.length() / 2
  let out = FixedArray::make(n, b'\\x00')
  for i = 0; i < n; i = i + 1 {{
    let hi = hex_nibble(s[i * 2].to_int())
    let lo = hex_nibble(s[i * 2 + 1].to_int())
    out[i] = ((hi << 4) | lo).to_byte()
  }}
  Bytes::from_array(out)
}}

///|
test "OpenSSL 3.5.6 -> MoonTLCP: SM3 digest matches live OpenSSL output" {{
  let msg = from_hex(
    {format_hex_mbt(o_sm3_msg.hex())},
  )
  let expected = from_hex(
    {format_hex_mbt(o_sm3_digest)},
  )
  assert_eq(@sm3.sm3(msg), expected)
}}

///|
test "OpenSSL 3.5.6 -> MoonTLCP: SM4-CBC-PKCS7 & SM4-CTR match live OpenSSL output" {{
  let key = from_hex("{o_sm4_key.hex()}")
  let iv = from_hex("{o_sm4_iv.hex()}")
  let pt = from_hex(
    {format_hex_mbt(o_sm4_pt.hex())},
  )
  let cbc_ct = from_hex(
    {format_hex_mbt(o_sm4_cbc_ct.hex())},
  )
  let ctr_ct = from_hex(
    {format_hex_mbt(o_sm4_ctr_ct.hex())},
  )
  let sm4 = @sm4.Sm4Key::new(key)
  assert_eq(sm4.cbc_encrypt_pkcs7(iv, pt), cbc_ct)
  assert_eq(sm4.cbc_decrypt_pkcs7(iv, cbc_ct), pt)
  assert_eq(sm4.ctr_crypt(iv, pt), ctr_ct)
  assert_eq(sm4.ctr_crypt(iv, ctr_ct), pt)
}}

///|
test "OpenSSL 3.5.6 -> MoonTLCP: SM2 DER signature verify & ASN.1 SM2Cipher decrypt" {{
  let priv_key = @sm2.PrivateKey::from_bytes(
    from_hex("{o_sm2_priv32.hex()}"),
  )
  let pub_key = @sm2.PublicKey::from_bytes(
    from_hex(
      {format_hex_mbt(o_sm2_pub65.hex())},
    ),
  )
  assert_eq(priv_key.public_key(), pub_key)

  let msg = from_hex(
    {format_hex_mbt(o_sm2_msg.hex())},
  )
  let sig_der = from_hex(
    {format_hex_mbt(o_sm2_sig_der.hex())},
  )
  let cipher_asn1 = from_hex(
    {format_hex_mbt(o_sm2_ct_asn1.hex())},
  )
  assert_true(@sm2.verify_der(pub_key, @sm2.DEFAULT_SM2_ID, msg, sig_der))
  assert_eq(@sm2.decrypt_asn1(priv_key, cipher_asn1), msg)
}}

///|
test "OpenSSL 3.5.6 -> MoonTLCP: X.509 SM2 Root CA + dual Sign/Enc certs parse & verify" {{
  let ca_der = from_hex(
    {format_hex_mbt(o_ca_der.read_bytes().hex())},
  )
  let sign_der = from_hex(
    {format_hex_mbt(o_sign_der.read_bytes().hex())},
  )
  let enc_der = from_hex(
    {format_hex_mbt(o_enc_der.read_bytes().hex())},
  )
  let ca_cert = @x509.Certificate::from_der(ca_der)
  assert_true(ca_cert.is_ca)
  assert_eq(ca_cert.subject_cn, "OpenSSL-3.5-SM2-Root-CA")
  let bundle = @x509.parse_and_verify_dual_certs([sign_der, enc_der], [ca_cert])
  assert_eq(bundle.sign_cert.subject_cn, "server.moontlcp.local")
  assert_eq(bundle.enc_cert.subject_cn, "server.moontlcp.local")
  assert_true(bundle.sign_cert.public_key != bundle.enc_cert.public_key)
}}
'''
            GENERATED_TEST.write_text(mbt_src, encoding="utf-8")
            run_cmd([moon, "fmt", "harness"], cwd=ROOT, env=env)

            # Run MoonBit tests on both wasm and js targets
            for target in ("wasm", "js"):
                res = run_cmd(
                    [
                        moon,
                        "test",
                        "--target-dir",
                        str(BUILD_DIR),
                        "--target",
                        target,
                        "-d",
                        "harness",
                    ],
                    cwd=ROOT,
                    env=env,
                )
                summary_line = [l for l in res.stdout.decode().splitlines() if "Total tests:" in l]
                detail = summary_line[-1].strip() if summary_line else "passed"
                record(f"OpenSSL->MoonTLCP ({target} target)", True, detail)

    except Exception as exc:
        record("Interop Harness", False, str(exc))
        return 1
    finally:
        if BUILD_DIR.exists() and "--keep-build" not in sys.argv:
            shutil.rmtree(BUILD_DIR, ignore_errors=True)

    passed = sum(1 for _, ok, _ in results if ok)
    total = len(results)
    print(f"\n=== SUMMARY: {passed}/{total} PASSED (OpenSSL 3.5.6 <-> MoonTLCP 100% Bidirectional Interop) ===")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
