///|
/// Minimum required CSPRNG entropy length (32 bytes / 256 bits) for deterministic
/// KEM encapsulation and public-key encryption.
pub const MIN_ENTROPY_LEN : Int32 = 32

///|
/// Maximum allowed KDF output length (16 MiB) to prevent OOM DoS and `Int32`
/// length arithmetic overflow (`k1_len + 32`).
pub const MAX_KDF_LEN : Int32 = 16_777_216

///|
/// Encryption mode for SM9 public-key encryption (GB/T 38635.4-2020).
/// - `KdfXor`: KDF-based stream cipher mode (Appendix A.2, `EnType = 0`).
/// - `Sm4EcbPkcs7`: SM4-ECB with PKCS#7 padding mode (Appendix A.3, `EnType = 1`).
#derive(Eq, Debug)
pub(all) enum EncMode {
  KdfXor
  Sm4EcbPkcs7
}

///|
/// Output of SM9 Key Encapsulation Mechanism (KEM, GB/T 38635.4-2020 Appendix A.1).
#derive(Eq, Debug)
pub struct KemOutput {
  key : Bytes
  c1 : @ec.G1Affine
}

///|
/// Returns the encapsulated shared secret key bytes `K`.
pub fn KemOutput::key(self : KemOutput) -> Bytes {
  self.key
}

///|
/// Returns the encapsulated ephemeral point `C1 in G1`.
pub fn KemOutput::c1(self : KemOutput) -> @ec.G1Affine {
  self.c1
}

///|
/// Returns the raw 64-byte encoding `x_C1 || y_C1` of `C1` (no `0x04` prefix).
pub fn KemOutput::c1_bytes_raw(self : KemOutput) -> Bytes {
  self.c1.to_bytes_raw()
}

///|
/// Returns the uncompressed 65-byte encoding `0x04 || x_C1 || y_C1` of `C1`.
pub fn KemOutput::c1_bytes_uncompressed(self : KemOutput) -> Bytes {
  self.c1.to_bytes_uncompressed()
}

///|
/// Thin adapter delegating SM4-ECB-PKCS#7 encryption to shared `crypto/sm4`.
fn sm4_encrypt_ecb_pkcs7(key : BytesView, plaintext : BytesView) -> Bytes? {
  try {
    let sm4 = @sm4.Sm4Key::new(key.to_owned())
    Some(sm4.ecb_encrypt_pkcs7(plaintext.to_owned()))
  } catch {
    _ => None
  }
}

///|
/// Thin adapter delegating SM4-ECB-PKCS#7 decryption to shared `crypto/sm4`.
fn sm4_decrypt_ecb_pkcs7(key : BytesView, ciphertext : BytesView) -> Bytes? {
  try {
    let sm4 = @sm4.Sm4Key::new(key.to_owned())
    Some(sm4.ecb_decrypt_pkcs7(ciphertext.to_owned()))
  } catch {
    _ => None
  }
}

///|
/// Constant-time full-scan check for whether every byte in `data` is zero.
/// Never exits early on a non-zero byte.
fn is_all_zero_ct(data : BytesView) -> Bool {
  let mut acc = 0
  for i = 0; i < data.length(); i = i + 1 {
    acc = acc | data[i].to_int()
  }
  acc == 0
}

///|
/// Writes a 32-bit unsigned integer in big-endian byte order into an SM3 hasher.
fn sm3_update_be_u32(h : @sm3.Sm3, v : UInt32) -> Unit {
  h.update_byte((v >> 24).to_byte())
  h.update_byte((v >> 16).to_byte())
  h.update_byte((v >> 8).to_byte())
  h.update_byte(v.to_byte())
}

///|
/// Writes a length-prefixed byte slice into an SM3 hasher for unambiguous domain separation.
fn sm3_update_len_prefixed(h : @sm3.Sm3, data : BytesView) -> Unit {
  sm3_update_be_u32(h, data.length().reinterpret_as_uint())
  h.update(data)
}

///|
/// Validates the encryption master public key `P_pub-e in G1 \ {O}`.
fn validate_p_pub_e(p_pub_e : @ec.G1Affine) -> Result[Unit, String] {
  if p_pub_e.is_infinity() {
    return Err("master public key P_pub-e is point at infinity")
  }
  if !p_pub_e.is_on_curve() {
    return Err("master public key P_pub-e is not on curve")
  }
  Ok(())
}

///|
/// Validates a `C1 in G1 \ {O}` point.
fn validate_c1(c1 : @ec.G1Affine) -> Result[Unit, String] {
  if c1.is_infinity() {
    return Err("C1 is point at infinity")
  }
  if !c1.is_on_curve() {
    return Err("C1 is not on curve")
  }
  Ok(())
}

///|
/// Validates the user decryption private key `de_B in G2 \ {O}` (including prime-order subgroup check).
fn validate_de_b(de_b : @ec.G2Affine) -> Result[Unit, String] {
  if de_b.is_infinity() {
    return Err("user private key de_B is point at infinity")
  }
  if !de_b.is_in_subgroup() {
    return Err("user private key de_B is not in G2 subgroup")
  }
  Ok(())
}

///|
/// Computes `Q_B = [H1(id_b || hid, N)]P1 + P_pub-e` in `G1`.
fn compute_qb(
  p_pub_e : @ec.G1Affine,
  id_b : BytesView,
  hid : Byte,
) -> @ec.G1Affine {
  let id_len = id_b.length()
  let z = Bytes::makei(id_len + 1, fn(i) {
    if i < id_len {
      id_b[i]
    } else {
      hid
    }
  })
  let h1_bytes = @sm3.h1(z, @field.order_n.to_be_bytes())
  let h1 = @field.Fn::from_be_bytes_mod(h1_bytes)
  @ec.G1Affine::generator().scalar_mul_fn(h1).add_mixed(p_pub_e).to_affine()
}

///|
/// Computes the bilinear pairing `e(Q, P)` for `Q in G2` and `P in G1`.
fn pair_g2_g1(q : @ec.G2Affine, p : @ec.G1Affine) -> @field.Fp12 {
  @pairing.pair_coords(q.x(), q.y(), p.x(), p.y())
}

///|
/// Builds the GB/T 38635.4 KDF input `C1_64B || FE2OS(w)_384B || ID_B`.
/// Strictly uses raw 64-byte `C1` without any `0x04` prefix.
fn build_kdf_input(c1_raw : Bytes, w : @field.Fp12, id_b : BytesView) -> Bytes {
  let w_bytes = w.to_bytes()
  let id_len = id_b.length()
  Bytes::makei(448 + id_len, fn(i) {
    if i < 64 {
      c1_raw[i]
    } else if i < 448 {
      w_bytes[i - 64]
    } else {
      id_b[i - 448]
    }
  })
}

///|
/// Concatenates raw ciphertext components in GB/T 38635.4 order: `C1 (64B) || C3 (32B) || C2`.
fn concat_c1_c3_c2(c1_raw : Bytes, c3 : Bytes, c2 : Bytes) -> Bytes {
  let c2_len = c2.length()
  Bytes::makei(96 + c2_len, fn(i) {
    if i < 64 {
      c1_raw[i]
    } else if i < 96 {
      c3[i - 64]
    } else {
      c2[i - 96]
    }
  })
}

///|
/// Domain-separated deterministic derivation of an ephemeral scalar `r in [1, N - 1]`
/// using SM3 and 320-bit unbiased modular reduction `(Ha mod (N - 1)) + 1`.
fn derive_r_deterministic(
  domain : BytesView,
  p_pub_e : @ec.G1Affine,
  id_b : BytesView,
  hid : Byte,
  extra : BytesView,
  entropy : BytesView,
  counter : UInt32,
) -> @field.Fn {
  let h = @sm3.Sm3::new()
  sm3_update_len_prefixed(h, domain)
  sm3_update_be_u32(h, counter)
  h.update_byte(hid)
  h.update(p_pub_e.to_bytes_raw())
  sm3_update_len_prefixed(h, id_b)
  sm3_update_len_prefixed(h, extra)
  sm3_update_len_prefixed(h, entropy)
  let seed = h.finalize()
  let r_bytes = @sm3.h1(seed, @field.order_n.to_be_bytes())
  @field.Fn::from_be_bytes_mod(r_bytes)
}

///|
/// Internal shared computation of `(C1, C1_raw, w)` given validated `P_pub-e` and non-zero `r`.
fn encapsulate_core(
  p_pub_e : @ec.G1Affine,
  id_b : BytesView,
  r : @field.Fn,
  hid : Byte,
) -> Result[(@ec.G1Affine, Bytes, @field.Fp12), String] {
  match validate_p_pub_e(p_pub_e) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  if r.is_zero() {
    return Err("ephemeral scalar r must be non-zero")
  }
  let qb = compute_qb(p_pub_e, id_b, hid)
  if qb.is_infinity() {
    return Err("derived public key Q_B is point at infinity")
  }
  let c1 = qb.scalar_mul_fn(r).to_affine()
  if c1.is_infinity() {
    return Err("C1 is point at infinity")
  }
  let p2 = @ec.G2Affine::generator()
  let g = pair_g2_g1(p2, p_pub_e)
  let w = g.cyclotomic_pow_u256(r.to_u256())
  Ok((c1, c1.to_bytes_raw(), w))
}

///|
/// SM9 Key Encapsulation Mechanism (KEM) with caller-supplied ephemeral scalar `r`
/// (GB/T 38635.4-2020 Appendix A.1).
///
/// Computes `Q_B = [H1(id_b || hid, N)]P1 + P_pub-e`, `C1 = [r]Q_B`, `w = e(P2, P_pub-e)^r`,
/// and `K = KDF(C1_64B || w_384B || id_b, klen)`. Rejects all-zero `K`.
pub fn kem_encapsulate_with_r(
  p_pub_e : @ec.G1Affine,
  id_b : BytesView,
  klen : Int32,
  r : @field.Fn,
  hid~ : Byte = b'\x03',
) -> Result[KemOutput, String] {
  if klen <= 0 || klen > MAX_KDF_LEN {
    return Err("klen must be in [1, MAX_KDF_LEN]")
  }
  let (c1, c1_raw, w) = match encapsulate_core(p_pub_e, id_b, r, hid) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let kdf_in = build_kdf_input(c1_raw, w, id_b)
  let key = @sm3.kdf(kdf_in, klen)
  if is_all_zero_ct(key) {
    return Err("derived key is all zero")
  }
  Ok({ key, c1, })
}

///|
/// Deterministic SM9 Key Encapsulation Mechanism (KEM) deriving ephemeral scalar `r`
/// via domain-separated SM3 from `entropy` (at least `MIN_ENTROPY_LEN` = 32 bytes from
/// a CSPRNG) and public parameters, automatically retrying with an incremented counter
/// if the derived key `K` is all zero.
pub fn kem_encapsulate_deterministic(
  p_pub_e : @ec.G1Affine,
  id_b : BytesView,
  klen : Int32,
  entropy : BytesView,
  hid~ : Byte = b'\x03',
) -> Result[KemOutput, String] {
  if entropy.length() < MIN_ENTROPY_LEN {
    return Err("entropy must be at least 32 bytes from a CSPRNG")
  }
  if klen <= 0 || klen > MAX_KDF_LEN {
    return Err("klen must be in [1, MAX_KDF_LEN]")
  }
  match validate_p_pub_e(p_pub_e) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let klen_u32 = klen.reinterpret_as_uint()
  let extra = Bytes::from_array([
    (klen_u32 >> 24).to_byte(),
    (klen_u32 >> 16).to_byte(),
    (klen_u32 >> 8).to_byte(),
    klen_u32.to_byte(),
  ])
  for ctr = 0U; ctr < 256U; ctr = ctr + 1U {
    let r = derive_r_deterministic(
      b"SM9-KEM-DET-R-v1", p_pub_e, id_b, hid, extra, entropy, ctr,
    )
    match kem_encapsulate_with_r(p_pub_e, id_b, klen, r, hid~) {
      Ok(out) => return Ok(out)
      Err(e) => if e != "derived key is all zero" { return Err(e) }
    }
  }
  Err("failed to derive non-zero KEM key after retries")
}

///|
/// SM9 Key Decapsulation Mechanism (GB/T 38635.4-2020 Appendix A.1).
///
/// Strictly validates `C1 in G1 \ {O}` and `de_B in G2 \ {O}` (with subgroup check),
/// computes `w = e(de_B, C1)` and `K = KDF(C1_64B || w_384B || id_b, klen)`,
/// and rejects all-zero `K`.
pub fn kem_decapsulate(
  id_b : BytesView,
  de_b : @ec.G2Affine,
  c1 : @ec.G1Affine,
  klen : Int32,
) -> Result[Bytes, String] {
  if klen <= 0 || klen > MAX_KDF_LEN {
    return Err("klen must be in [1, MAX_KDF_LEN]")
  }
  match validate_c1(c1) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  match validate_de_b(de_b) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let w = pair_g2_g1(de_b, c1)
  let kdf_in = build_kdf_input(c1.to_bytes_raw(), w, id_b)
  let key = @sm3.kdf(kdf_in, klen)
  if is_all_zero_ct(key) {
    return Err("derived key is all zero")
  }
  Ok(key)
}

///|
/// SM9 Public-Key Encryption with caller-supplied ephemeral scalar `r`
/// (GB/T 38635.4-2020 Appendix A.2 `KdfXor` and Appendix A.3 `Sm4EcbPkcs7`).
///
/// Outputs the standard raw ciphertext layout `C1 (64B) || C3 (32B) || C2`,
/// where `C3 = SM3(C2 || K2)`.
pub fn encrypt_with_r(
  p_pub_e : @ec.G1Affine,
  id_b : BytesView,
  plaintext : BytesView,
  r : @field.Fn,
  mode~ : EncMode = KdfXor,
  hid~ : Byte = b'\x03',
) -> Result[Bytes, String] {
  match mode {
    KdfXor =>
      if plaintext.length() > MAX_KDF_LEN - 32 {
        return Err("plaintext exceeds maximum KdfXor length (MAX_KDF_LEN - 32)")
      }
    Sm4EcbPkcs7 => ()
  }
  let (_, c1_raw, w) = match encapsulate_core(p_pub_e, id_b, r, hid) {
    Ok(v) => v
    Err(e) => return Err(e)
  }
  let kdf_in = build_kdf_input(c1_raw, w, id_b)
  match mode {
    KdfXor => {
      let k1_len = plaintext.length()
      let k = @sm3.kdf(kdf_in, k1_len + 32)
      let k1 = k[0:k1_len]
      let k2 = k[k1_len:k1_len + 32]
      if k1_len > 0 && is_all_zero_ct(k1) {
        return Err("derived key K1 is all zero")
      }
      let c2 = Bytes::makei(k1_len, fn(i) {
        (plaintext[i].to_int() ^ k1[i].to_int()).to_byte()
      })
      let c3 = @sm3.mac(k2, c2)
      Ok(concat_c1_c3_c2(c1_raw, c3, c2))
    }
    Sm4EcbPkcs7 => {
      let k = @sm3.kdf(kdf_in, 48)
      let k1 = k[0:16]
      let k2 = k[16:48]
      if is_all_zero_ct(k1) {
        return Err("derived key K1 is all zero")
      }
      let c2 = match sm4_encrypt_ecb_pkcs7(k1, plaintext) {
        Some(ct) => ct
        None => return Err("SM4-ECB-PKCS7 encryption failed")
      }
      let c3 = @sm3.mac(k2, c2)
      Ok(concat_c1_c3_c2(c1_raw, c3, c2))
    }
  }
}

///|
/// Deterministic SM9 Public-Key Encryption deriving ephemeral scalar `r` via domain-separated
/// SM3 from `entropy` (at least `MIN_ENTROPY_LEN` = 32 bytes from a CSPRNG), `mode`,
/// `plaintext` digest, and public parameters, automatically retrying with an incremented
/// counter if `K1` is all zero.
pub fn encrypt_deterministic(
  p_pub_e : @ec.G1Affine,
  id_b : BytesView,
  plaintext : BytesView,
  entropy : BytesView,
  mode~ : EncMode = KdfXor,
  hid~ : Byte = b'\x03',
) -> Result[Bytes, String] {
  if entropy.length() < MIN_ENTROPY_LEN {
    return Err("entropy must be at least 32 bytes from a CSPRNG")
  }
  match mode {
    KdfXor =>
      if plaintext.length() > MAX_KDF_LEN - 32 {
        return Err("plaintext exceeds maximum KdfXor length (MAX_KDF_LEN - 32)")
      }
    Sm4EcbPkcs7 => ()
  }
  match validate_p_pub_e(p_pub_e) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let mode_byte : Byte = match mode {
    KdfXor => b'\x00'
    Sm4EcbPkcs7 => b'\x01'
  }
  let pt_hash = @sm3.hash(plaintext)
  let extra = Bytes::makei(33, fn(i) {
    if i == 0 {
      mode_byte
    } else {
      pt_hash[i - 1]
    }
  })
  for ctr = 0U; ctr < 256U; ctr = ctr + 1U {
    let r = derive_r_deterministic(
      b"SM9-ENC-DET-R-v1", p_pub_e, id_b, hid, extra, entropy, ctr,
    )
    match encrypt_with_r(p_pub_e, id_b, plaintext, r, mode~, hid~) {
      Ok(ct) => return Ok(ct)
      Err(e) => if e != "derived key K1 is all zero" { return Err(e) }
    }
  }
  Err("failed to derive non-zero encryption key after retries")
}

///|
/// SM9 Public-Key Decryption (GB/T 38635.4-2020 Appendix A.2 `KdfXor` and Appendix A.3 `Sm4EcbPkcs7`).
///
/// Expects raw ciphertext `C1 (64B) || C3 (32B) || C2`.
/// Strictly validates public ciphertext lengths before pairing, validates `C1` on `G1`
/// (rejecting infinity, out-of-range coordinates, and off-curve points) and `de_B` in `G2`
/// subgroup, and verifies `C3 = SM3(C2 || K2)` and `K1 != 0` in constant time without
/// distinguishing MAC failure from all-zero `K1` to prevent IND-CCA2 and padding oracles.
pub fn decrypt(
  id_b : BytesView,
  de_b : @ec.G2Affine,
  ciphertext : BytesView,
  mode~ : EncMode = KdfXor,
) -> Result[Bytes, String] {
  if ciphertext.length() < 96 {
    return Err("ciphertext too short (must be at least 96 bytes)")
  }
  let c2_len = ciphertext.length() - 96
  match mode {
    KdfXor => if c2_len > MAX_KDF_LEN - 32 { return Err("decryption failed") }
    Sm4EcbPkcs7 =>
      if c2_len == 0 || c2_len % 16 != 0 {
        return Err("decryption failed")
      }
  }
  match validate_de_b(de_b) {
    Err(e) => return Err(e)
    Ok(_) => ()
  }
  let c1_raw_view = ciphertext[0:64]
  let c1 = match @ec.G1Affine::from_bytes_raw_strict(c1_raw_view) {
    Some(pt) => pt
    None => return Err("invalid C1 point in ciphertext")
  }
  let c3 = ciphertext[64:96]
  let c2 = ciphertext[96:]
  let w = pair_g2_g1(de_b, c1)
  let kdf_in = build_kdf_input(c1.to_bytes_raw(), w, id_b)
  match mode {
    KdfXor => {
      let k1_len = c2.length()
      let k = @sm3.kdf(kdf_in, k1_len + 32)
      let k1 = k[0:k1_len]
      let k2 = k[k1_len:k1_len + 32]
      let expected_c3 = @sm3.mac(k2, c2)
      let mac_ok = @sm3.ct_eq_bytes(expected_c3, c3)
      let k1_nonzero = if k1_len > 0 { !is_all_zero_ct(k1) } else { true }
      let valid = (@field.ct_mask(mac_ok) & @field.ct_mask(k1_nonzero)) != 0UL
      if !valid {
        return Err("decryption failed")
      }
      let plaintext = Bytes::makei(k1_len, fn(i) {
        (c2[i].to_int() ^ k1[i].to_int()).to_byte()
      })
      Ok(plaintext)
    }
    Sm4EcbPkcs7 => {
      let k = @sm3.kdf(kdf_in, 48)
      let k1 = k[0:16]
      let k2 = k[16:48]
      let expected_c3 = @sm3.mac(k2, c2)
      let mac_ok = @sm3.ct_eq_bytes(expected_c3, c3)
      let k1_nonzero = !is_all_zero_ct(k1)
      let valid = (@field.ct_mask(mac_ok) & @field.ct_mask(k1_nonzero)) != 0UL
      if !valid {
        return Err("decryption failed")
      }
      match sm4_decrypt_ecb_pkcs7(k1, c2) {
        Some(plaintext) => Ok(plaintext)
        None => Err("decryption failed")
      }
    }
  }
}
