///|
/// Private key generation function identifier for SM9 digital signatures (GB/T 38635.2).
pub const HID_SIGN : Byte = @kgc.HID_SIGN

///|
/// Private key generation function identifier for SM9 key exchange (GB/T 38635.3).
pub const HID_KEYEX : Byte = @kgc.HID_KEYEX

///|
/// Private key generation function identifier for SM9 KEM and public-key encryption (GB/T 38635.4).
pub const HID_ENC : Byte = @kgc.HID_ENC

///|
/// Minimum required CSPRNG entropy length (32 bytes / 256 bits) for `kem_encapsulate` and `encrypt`.
pub const MIN_ENTROPY_LEN : Int32 = @enc.MIN_ENTROPY_LEN

///|
/// Computes the 32-byte SM3 cryptographic hash digest (GB/T 32905-2016).
pub fn sm3_hash(data : BytesView) -> Bytes {
  @sm3.hash(data)
}

///|
/// Computes the lowercase 64-character hexadecimal SM3 digest of `data`.
pub fn sm3_hex(data : BytesView) -> String {
  @sm3.hash_hex(data)
}

///|
/// SM9 Key Derivation Function `KDF(Z, klen)` based on SM3 (GB/T 38635.1 §5.4.3).
pub fn kdf(z : BytesView, klen : Int32) -> Bytes {
  @sm3.kdf(z, klen)
}

///|
/// SM9 Message Authentication Code `MAC(K2, Z) = SM3(Z || K2)` (GB/T 38635.1 §5.4.5).
pub fn mac(k2 : BytesView, data : BytesView) -> Bytes {
  @sm3.mac(k2, data)
}

///|
/// Encodes a byte slice as a lowercase hexadecimal string.
pub fn bytes_to_hex(data : BytesView) -> String {
  @sm3.bytes_to_hex(data)
}

///|
/// Decodes an even-length hexadecimal string (case-insensitive) into bytes.
pub fn hex_to_bytes(hex : String) -> Bytes? {
  @sm3.hex_to_bytes(hex)
}

///|
/// Constant-time byte-slice equality comparison.
pub fn ct_eq_bytes(a : BytesView, b : BytesView) -> Bool {
  @sm3.ct_eq_bytes(a, b)
}

///|
/// Encrypts `plaintext` with 16-byte SM4 key in ECB mode with PKCS#7 padding (GB/T 32907-2016),
/// delegating directly to the shared `CoolrfulDARkness/moontlcp/crypto/sm4` core.
pub fn sm4_encrypt_ecb_pkcs7(key : BytesView, plaintext : BytesView) -> Bytes? {
  try {
    let sm4 = @sm4.Sm4Key::new(key.to_owned())
    Some(sm4.ecb_encrypt_pkcs7(plaintext.to_owned()))
  } catch {
    _ => None
  }
}

///|
/// Decrypts `ciphertext` with 16-byte SM4 key in ECB mode with constant-time PKCS#7 unpadding,
/// delegating directly to the shared `CoolrfulDARkness/moontlcp/crypto/sm4` core.
pub fn sm4_decrypt_ecb_pkcs7(key : BytesView, ciphertext : BytesView) -> Bytes? {
  try {
    let sm4 = @sm4.Sm4Key::new(key.to_owned())
    Some(sm4.ecb_decrypt_pkcs7(ciphertext.to_owned()))
  } catch {
    _ => None
  }
}

///|
/// Computes the BN256 optimal R-ate bilinear pairing `e(Q, P) in GT` for `Q in G2` and `P in G1`.
/// Returns `Fp12::one()` when either point is the point at infinity.
pub fn pair(q : @ec.G2Affine, p : @ec.G1Affine) -> @field.Fp12 {
  if q.is_infinity() || p.is_infinity() {
    @field.Fp12::one()
  } else {
    @pairing.pair_coords(q.x(), q.y(), p.x(), p.y())
  }
}

///|
/// Computes the product of two BN256 optimal R-ate pairings `e(Q1, P1) * e(Q2, P2)`
/// with a shared final exponentiation for improved performance.
pub fn pair_product(
  q1 : @ec.G2Affine,
  p1 : @ec.G1Affine,
  q2 : @ec.G2Affine,
  p2 : @ec.G1Affine,
) -> @field.Fp12 {
  if q1.is_infinity() || p1.is_infinity() {
    pair(q2, p2)
  } else if q2.is_infinity() || p2.is_infinity() {
    pair(q1, p1)
  } else {
    @pairing.pair_product_coords(
      q1.x(),
      q1.y(),
      p1.x(),
      p1.y(),
      q2.x(),
      q2.y(),
      p2.x(),
      p2.y(),
    )
  }
}

///|
/// Deterministically derives an SM9 signing master private key `ks in [1, N - 1]` from `seed`.
pub fn sign_master_from_seed(seed : BytesView) -> @kgc.SignMasterPrivateKey {
  @kgc.SignMasterPrivateKey::from_seed(seed)
}

///|
/// Strictly parses a 32-byte big-endian signing master private key `ks in [1, N - 1]`.
pub fn sign_master_from_bytes(b : BytesView) -> @kgc.SignMasterPrivateKey? {
  @kgc.SignMasterPrivateKey::from_bytes_strict(b)
}

///|
/// Extracts a user signing private key `ds in G1` for identity `id` (GB/T 38635.2).
pub fn extract_sign_key(
  master : @kgc.SignMasterPrivateKey,
  id : BytesView,
  hid~ : Byte = HID_SIGN,
) -> Result[@kgc.SignUserPrivateKey, String] {
  @kgc.extract_sign_private_key(master, id, hid~)
}

///|
/// Deterministically derives an SM9 encryption / key-exchange master private key `ke in [1, N - 1]`
/// from `seed`.
pub fn enc_master_from_seed(seed : BytesView) -> @kgc.EncMasterPrivateKey {
  @kgc.EncMasterPrivateKey::from_seed(seed)
}

///|
/// Strictly parses a 32-byte big-endian encryption / key-exchange master private key `ke in [1, N - 1]`.
pub fn enc_master_from_bytes(b : BytesView) -> @kgc.EncMasterPrivateKey? {
  @kgc.EncMasterPrivateKey::from_bytes_strict(b)
}

///|
/// Extracts a user key-exchange private key `de in G2` for identity `id` (GB/T 38635.3, default `hid = 0x02`).
pub fn extract_keyex_key(
  master : @kgc.EncMasterPrivateKey,
  id : BytesView,
  hid~ : Byte = HID_KEYEX,
) -> Result[@kgc.EncUserPrivateKey, String] {
  @kgc.extract_keyex_private_key(master, id, hid~)
}

///|
/// Extracts a user encryption / KEM private key `de in G2` for identity `id` (GB/T 38635.4, default `hid = 0x03`).
pub fn extract_enc_key(
  master : @kgc.EncMasterPrivateKey,
  id : BytesView,
  hid~ : Byte = HID_ENC,
) -> Result[@kgc.EncUserPrivateKey, String] {
  @kgc.extract_enc_private_key(master, id, hid~)
}

///|
/// Deterministically signs `msg` under master signing public key `p_pub_s` and user signing
/// private key `ds` (GB/T 38635.2). Optional caller `entropy` is mixed into the nonce derivation.
pub fn sign(
  p_pub_s : @kgc.SignMasterPublicKey,
  ds : @kgc.SignUserPrivateKey,
  msg : BytesView,
  entropy~ : BytesView = b"",
) -> Result[@sign.Signature, String] {
  @sign.sign_deterministic(p_pub_s.to_g2(), ds.to_g1(), msg, entropy)
}

///|
/// Signs `msg` using a caller-supplied non-zero nonce `r in [1, N - 1]` (GB/T 38635.2).
pub fn sign_with_r(
  p_pub_s : @kgc.SignMasterPublicKey,
  ds : @kgc.SignUserPrivateKey,
  msg : BytesView,
  r : @field.Fn,
) -> Result[@sign.Signature, String] {
  @sign.sign_with_r(p_pub_s.to_g2(), ds.to_g1(), msg, r)
}

///|
/// Verifies an SM9 signature `(h, S)` for identity `id` and message `msg` (GB/T 38635.2).
pub fn verify(
  p_pub_s : @kgc.SignMasterPublicKey,
  id : BytesView,
  msg : BytesView,
  sig : @sign.Signature,
  hid~ : Byte = HID_SIGN,
) -> Bool {
  @sign.verify(p_pub_s.to_g2(), id, msg, sig, hid~)
}

///|
/// Generates an SM9 key-exchange ephemeral point `R = [r]Q_peer` in `G1` (GB/T 38635.3).
pub fn keyex_ephemeral(
  p_pub_e : @kgc.EncMasterPublicKey,
  peer_id : BytesView,
  r : @field.Fn,
  hid~ : Byte = HID_KEYEX,
) -> Result[@ec.G1Affine, String] {
  @keyex.generate_ephemeral(p_pub_e.to_g1(), peer_id, r, hid~)
}

///|
/// Executes the SM9 key-exchange responder protocol (User B, GB/T 38635.3).
pub fn keyex_responder(
  p_pub_e : @kgc.EncMasterPublicKey,
  id_a : BytesView,
  id_b : BytesView,
  de_b : @kgc.EncUserPrivateKey,
  r_b : @field.Fn,
  r_a_point : @ec.G1Affine,
  r_b_point : @ec.G1Affine,
  klen : Int32,
) -> Result[@keyex.ResponderResult, String] {
  @keyex.responder_exchange(
    p_pub_e.to_g1(),
    id_a,
    id_b,
    de_b.to_g2(),
    r_b,
    r_a_point,
    r_b_point,
    klen,
  )
}

///|
/// Executes the SM9 key-exchange initiator protocol (User A, GB/T 38635.3).
/// When `peer_s_b` is supplied, verifies `S_1 == peer_s_b` in constant time before deriving `SK_A`.
pub fn keyex_initiator(
  p_pub_e : @kgc.EncMasterPublicKey,
  id_a : BytesView,
  id_b : BytesView,
  de_a : @kgc.EncUserPrivateKey,
  r_a : @field.Fn,
  r_a_point : @ec.G1Affine,
  r_b_point : @ec.G1Affine,
  klen : Int32,
  peer_s_b? : BytesView,
) -> Result[@keyex.InitiatorResult, String] {
  @keyex.initiator_exchange(
    p_pub_e.to_g1(),
    id_a,
    id_b,
    de_a.to_g2(),
    r_a,
    r_a_point,
    r_b_point,
    klen,
    peer_s_b?,
  )
}

///|
/// Constant-time responder verification of the initiator's 32-byte confirmation tag `S_A`
/// against `expected_s2` (GB/T 38635.3 Step B9).
pub fn keyex_verify_confirmation(
  expected_s2 : BytesView,
  received_sa : BytesView,
) -> Bool {
  @keyex.verify_responder_confirmation(expected_s2, received_sa)
}

///|
/// Encapsulates a `klen`-byte shared key for identity `id_b` (GB/T 38635.4 KEM).
///
/// Security: `entropy` is required and MUST come from a CSPRNG with at least
/// `MIN_ENTROPY_LEN` (32) bytes. Shorter entropy is rejected with `Err`.
pub fn kem_encapsulate(
  p_pub_e : @kgc.EncMasterPublicKey,
  id_b : BytesView,
  klen : Int32,
  entropy : BytesView,
  hid~ : Byte = HID_ENC,
) -> Result[@enc.KemOutput, String] {
  @enc.kem_encapsulate_deterministic(p_pub_e.to_g1(), id_b, klen, entropy, hid~)
}

///|
/// Encapsulates a `klen`-byte shared key for `id_b` with caller-supplied non-zero scalar `r`
/// (GB/T 38635.4 Appendix A.1).
pub fn kem_encapsulate_with_r(
  p_pub_e : @kgc.EncMasterPublicKey,
  id_b : BytesView,
  klen : Int32,
  r : @field.Fn,
  hid~ : Byte = HID_ENC,
) -> Result[@enc.KemOutput, String] {
  @enc.kem_encapsulate_with_r(p_pub_e.to_g1(), id_b, klen, r, hid~)
}

///|
/// Decapsulates a `klen`-byte shared key from `c1` using recipient private key `de_b`
/// (GB/T 38635.4 Appendix A.1).
pub fn kem_decapsulate(
  id_b : BytesView,
  de_b : @kgc.EncUserPrivateKey,
  c1 : @ec.G1Affine,
  klen : Int32,
) -> Result[Bytes, String] {
  @enc.kem_decapsulate(id_b, de_b.to_g2(), c1, klen)
}

///|
/// Encrypts `plaintext` for identity `id_b`, producing raw `C1 || C3 || C2` ciphertext
/// in either `@enc.EncMode::KdfXor` (default) or `@enc.EncMode::Sm4EcbPkcs7` mode
/// (GB/T 38635.4).
///
/// Security: `entropy` is required and MUST come from a CSPRNG with at least
/// `MIN_ENTROPY_LEN` (32) bytes. Shorter entropy is rejected with `Err`.
pub fn encrypt(
  p_pub_e : @kgc.EncMasterPublicKey,
  id_b : BytesView,
  plaintext : BytesView,
  entropy : BytesView,
  mode~ : @enc.EncMode = @enc.EncMode::KdfXor,
  hid~ : Byte = HID_ENC,
) -> Result[Bytes, String] {
  @enc.encrypt_deterministic(
    p_pub_e.to_g1(),
    id_b,
    plaintext,
    entropy,
    mode~,
    hid~,
  )
}

///|
/// Encrypts `plaintext` for identity `id_b` with caller-supplied non-zero scalar `r`, producing
/// raw `C1 || C3 || C2` ciphertext (GB/T 38635.4 Appendix A.2 / A.3).
pub fn encrypt_with_r(
  p_pub_e : @kgc.EncMasterPublicKey,
  id_b : BytesView,
  plaintext : BytesView,
  r : @field.Fn,
  mode~ : @enc.EncMode = @enc.EncMode::KdfXor,
  hid~ : Byte = HID_ENC,
) -> Result[Bytes, String] {
  @enc.encrypt_with_r(p_pub_e.to_g1(), id_b, plaintext, r, mode~, hid~)
}

///|
/// Decrypts a raw `C1 || C3 || C2` ciphertext for identity `id_b` using `de_b` (GB/T 38635.4).
/// Validates `C1`, `de_b`, and constant-time MAC `C3 = SM3(C2 || K2)` and `K1 != 0` before
/// decrypting `C2`, returning a uniform `Err("decryption failed")` for ciphertext/MAC/padding
/// failures to prevent IND-CCA2 and padding oracles.
pub fn decrypt(
  id_b : BytesView,
  de_b : @kgc.EncUserPrivateKey,
  ciphertext : BytesView,
  mode~ : @enc.EncMode = @enc.EncMode::KdfXor,
) -> Result[Bytes, String] {
  @enc.decrypt(id_b, de_b.to_g2(), ciphertext, mode~)
}
