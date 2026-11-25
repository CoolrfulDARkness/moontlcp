///|
fn to_hex(data : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i = 0; i < data.length(); i = i + 1 {
    let v = data[i].to_int()
    buf.write_char(digits[(v >> 4) & 0xF].to_int().unsafe_to_char())
    buf.write_char(digits[v & 0xF].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
fn emit(key : String, val : Bytes) -> Unit {
  println("\{key}=\{to_hex(val)}")
}

///|
/// Emits deterministic MoonTLCP cryptographic outputs and X.509 SM2 dual-cert PKI
/// artifacts as KEY=HEX lines for live verification by OpenSSL 3.5.6.
fn main {
  // 1. SM3 digest
  let sm3_msg = b"MoonTLCP <-> OpenSSL 3.5.6 bidirectional SM3 interoperability check!"
  emit("SM3_MSG", sm3_msg)
  emit("SM3_DIGEST", @sm3.sm3(sm3_msg))

  // 2. SM4-CBC-PKCS7 & SM4-CTR
  let sm4_key = b"\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
  let sm4_iv = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
  let sm4_pt = b"TLCP 1.1 SM4-CBC & SM4-CTR cross-language verification payload (45B+)"
  let k = try! @sm4.Sm4Key::new(sm4_key)
  emit("SM4_KEY", sm4_key)
  emit("SM4_IV", sm4_iv)
  emit("SM4_PT", sm4_pt)
  emit("SM4_CBC_CT", try! k.cbc_encrypt_pkcs7(sm4_iv, sm4_pt))
  emit("SM4_CTR_CT", try! k.ctr_crypt(sm4_iv, sm4_pt))

  // 3. SM2 Sign (DER) & Encrypt (ASN.1 SM2Cipher)
  let sk = try! @sm2.derive_keypair_from_seed(
    b"moontlcp-interop-sm2-keypair-seed-v1",
  )
  let pk = sk.public_key()
  let sm2_msg = b"GB/T 32918-2016 SM2 signature verified by OpenSSL 3.5.6"
  let sm2_sig = try! @sm2.sign_der(sk, @sm2.DEFAULT_SM2_ID, sm2_msg)
  let sm2_enc_pt = b"GM/T 0024-2023 PreMasterSecret encrypted by MoonTLCP SM2 ASN.1!"
  let sm2_cipher = try! @sm2.encrypt_asn1(
    pk, sm2_enc_pt, b"moontlcp-interop-enc-seed-v1",
  )
  emit("SM2_PRIV", sk.to_bytes())
  emit("SM2_PUB_UNCOMPRESSED", pk.to_uncompressed_bytes())
  emit("SM2_MSG", sm2_msg)
  emit("SM2_SIG_DER", sm2_sig)
  emit("SM2_ENC_PT", sm2_enc_pt)
  emit("SM2_CIPHER_ASN1", sm2_cipher)

  // 4. X.509 SM2 Root CA + Server Sign Cert + Server Enc Cert
  let pki = try! @x509.generate_test_pki(b"moontlcp-openssl-interop-pki-v1")
  emit("X509_CA_DER", pki.ca_cert.raw_der)
  emit("X509_SIGN_DER", pki.server_sign_cert.raw_der)
  emit("X509_ENC_DER", pki.server_enc_cert.raw_der)
}
