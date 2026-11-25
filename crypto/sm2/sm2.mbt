///|
/// GB/T 32918-2016 SM2 Public Key Cryptographic Algorithm Suite:
/// - Part 1: General & Key Pair Management (uncompressed/raw/compressed keys)
/// - Part 2: Digital Signature Algorithm (raw + ASN.1 DER, RFC 6979 HMAC-SM3)
/// - Part 3: Key Exchange Protocol (initiator & responder with S1/S2 confirmation)
/// - Part 4: Public Key Encryption Algorithm (C1C3C2 + ASN.1 DER SM2Cipher)

///|
pub const DEFAULT_SM2_ID : Bytes = b"1234567812345678"

///|
#derive(Debug, Eq)
pub suberror Sm2Error {
  InvalidPrivateKey
  InvalidPublicKey
  InvalidSignature
  InvalidCiphertext
  DecryptionFailed
  KeyExchangeFailed
  InvalidLength(Int32)
}

///|
pub struct PrivateKey {
  priv d : U256
  priv pub_x : U256
  priv pub_y : U256
}

///|
#derive(Debug)
pub struct PublicKey {
  priv x : U256
  priv y : U256
}

///|
pub impl Eq for PublicKey with fn equal(self, other) {
  u256_eq(self.x, other.x) && u256_eq(self.y, other.y)
}

///|
pub impl Eq for PrivateKey with fn equal(self, other) {
  u256_eq(self.d, other.d)
}

///|
#derive(Debug, Eq)
pub struct KeyExchangeResult {
  shared_key : Bytes
  s1 : Bytes
  s2 : Bytes
}

// ============================================================================
// PrivateKey & PublicKey API
// ============================================================================

///|
/// Constructs a validated SM2 private key from a 32-byte big-endian scalar.
/// Enforces `1 <= d <= n - 2` per GB/T 32918.1.
pub fn PrivateKey::from_bytes(bytes : Bytes) -> PrivateKey raise Sm2Error {
  if bytes.length() != 32 {
    raise InvalidLength(bytes.length())
  }
  let d = u256_from_be_view(bytes[:])
  if !sn_is_valid_privkey(d) {
    raise InvalidPrivateKey
  }
  let pt = scalar_mul_base(d)
  if pt.is_inf {
    raise InvalidPrivateKey
  }
  { d, pub_x: pt.x, pub_y: pt.y, }
}

///|
/// Serializes the private key scalar to 32-byte big-endian `Bytes`.
pub fn PrivateKey::to_bytes(self : PrivateKey) -> Bytes {
  u256_to_be_bytes(self.d)
}

///|
/// Returns the corresponding SM2 public key `P = d * G`.
pub fn PrivateKey::public_key(self : PrivateKey) -> PublicKey {
  { x: u256_clone(self.pub_x), y: u256_clone(self.pub_y), }
}

///|
/// Parses and strictly validates an SM2 public key from:
/// - 65-byte uncompressed SEC1 format `0x04 || X || Y`
/// - 64-byte raw coordinates `X || Y`
/// - 33-byte compressed SEC1 format `0x02/0x03 || X`
/// Rejects non-canonical coordinates (`>= p`), point at infinity, and off-curve points.
pub fn PublicKey::from_bytes(bytes : Bytes) -> PublicKey raise Sm2Error {
  match bytes.length() {
    65 => {
      if bytes[0] != b'\x04' {
        raise InvalidPublicKey
      }
      let x = u256_from_be_view(bytes[1:33])
      let y = u256_from_be_view(bytes[33:65])
      if !point_is_on_curve(x, y) {
        raise InvalidPublicKey
      }
      { x, y, }
    }
    64 => {
      let x = u256_from_be_view(bytes[0:32])
      let y = u256_from_be_view(bytes[32:64])
      if !point_is_on_curve(x, y) {
        raise InvalidPublicKey
      }
      { x, y, }
    }
    33 => {
      let prefix = bytes[0]
      if prefix != b'\x02' && prefix != b'\x03' {
        raise InvalidPublicKey
      }
      let x = u256_from_be_view(bytes[1:33])
      let want_odd = prefix == b'\x03'
      match point_decompress(x, want_odd) {
        Some(pt) => { x: pt.x, y: pt.y, }
        None => raise InvalidPublicKey
      }
    }
    _ => raise InvalidPublicKey
  }
}

///|
/// Encodes the public key as 65-byte uncompressed SEC1 format `0x04 || X || Y`.
pub fn PublicKey::to_uncompressed_bytes(self : PublicKey) -> Bytes {
  let xb = u256_to_be_bytes(self.x)
  let yb = u256_to_be_bytes(self.y)
  let out = FixedArray::make(65, b'\x00')
  out[0] = b'\x04'
  for i = 0; i < 32; i = i + 1 {
    out[1 + i] = xb[i]
    out[33 + i] = yb[i]
  }
  Bytes::from_array(out)
}

///|
/// Encodes the public key as 33-byte compressed SEC1 format `0x02/0x03 || X`.
pub fn PublicKey::to_compressed_bytes(self : PublicKey) -> Bytes {
  let xb = u256_to_be_bytes(self.x)
  let out = FixedArray::make(33, b'\x00')
  out[0] = if (self.y.limbs[0] & 1U) == 1U { b'\x03' } else { b'\x02' }
  for i = 0; i < 32; i = i + 1 {
    out[1 + i] = xb[i]
  }
  Bytes::from_array(out)
}

///|
/// Encodes the public key as 64-byte raw `X || Y`.
pub fn PublicKey::to_xy_bytes(self : PublicKey) -> Bytes {
  let xb = u256_to_be_bytes(self.x)
  let yb = u256_to_be_bytes(self.y)
  let out = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    out[i] = xb[i]
    out[32 + i] = yb[i]
  }
  Bytes::from_array(out)
}

///|
/// Returns the 32-byte big-endian X coordinate.
pub fn PublicKey::x_bytes(self : PublicKey) -> Bytes {
  u256_to_be_bytes(self.x)
}

///|
/// Returns the 32-byte big-endian Y coordinate.
pub fn PublicKey::y_bytes(self : PublicKey) -> Bytes {
  u256_to_be_bytes(self.y)
}

///|
/// Validates that the public key point is on the SM2 curve with canonical coordinates.
pub fn PublicKey::is_valid(self : PublicKey) -> Bool {
  point_is_on_curve(self.x, self.y)
}

///|
fn PublicKey::to_affine(self : PublicKey) -> AffinePoint {
  { x: u256_clone(self.x), y: u256_clone(self.y), is_inf: false, }
}

///|
fn write_be32(buf : FixedArray[Byte], off : Int32, v : UInt32) -> Unit {
  buf[off] = ((v >> 24) & 0xFFU).to_byte()
  buf[off + 1] = ((v >> 16) & 0xFFU).to_byte()
  buf[off + 2] = ((v >> 8) & 0xFFU).to_byte()
  buf[off + 3] = (v & 0xFFU).to_byte()
}

///|
/// Deterministically derives an SM2 private key from `seed` using SM3,
/// guaranteed to lie in `[1, n - 2]`.
pub fn derive_keypair_from_seed(seed : Bytes) -> PrivateKey raise Sm2Error {
  if seed.length() == 0 {
    raise InvalidLength(0)
  }
  let ctr_buf = FixedArray::make(4, b'\x00')
  let mut ctr : UInt32 = 0U
  for attempt = 0; attempt < 1024; attempt = attempt + 1 {
    write_be32(ctr_buf, 0, ctr)
    let h = @sm3.Sm3::new()
    h.update(b"SM2-KEYGEN-V1")
    h.update(seed)
    h.update(Bytes::from_array(ctr_buf))
    let candidate = h.finalize()
    let d = u256_from_be_view(candidate[:])
    if sn_is_valid_privkey(d) {
      let pt = scalar_mul_base(d)
      if !pt.is_inf {
        return { d, pub_x: pt.x, pub_y: pt.y, }
      }
    }
    ctr = ctr + 1U
  }
  raise InvalidPrivateKey
}

// ============================================================================
// Part 2: SM2 Digital Signature Algorithm (GB/T 32918.2-2016)
// ============================================================================

///|
/// Computes the user identity hash `Z_A = SM3(ENTL_A || ID_A || a || b || x_G || y_G || x_A || y_A)`.
pub fn compute_za(id : Bytes, pubkey : PublicKey) -> Bytes {
  let bit_len = id.length() * 8
  let entl = FixedArray::make(2, b'\x00')
  entl[0] = ((bit_len >> 8) & 0xFF).to_byte()
  entl[1] = (bit_len & 0xFF).to_byte()
  let h = @sm3.Sm3::new()
  h.update(Bytes::from_array(entl))
  h.update(id)
  h.update(u256_to_be_bytes(u256_from_limbs(sm2_a)))
  h.update(u256_to_be_bytes(u256_from_limbs(sm2_b)))
  h.update(u256_to_be_bytes(u256_from_limbs(sm2_gx)))
  h.update(u256_to_be_bytes(u256_from_limbs(sm2_gy)))
  h.update(pubkey.x_bytes())
  h.update(pubkey.y_bytes())
  h.finalize()
}

///|
/// Computes the SM2 message digest `e = SM3(Z_A || msg)`.
pub fn compute_digest(id : Bytes, pubkey : PublicKey, msg : Bytes) -> Bytes {
  let za = compute_za(id, pubkey)
  let h = @sm3.Sm3::new()
  h.update(za)
  h.update(msg)
  h.finalize()
}

///|
/// Internal helper: signs precomputed digest `e_bytes` with validated scalar `k_sc`.
fn sign_digest_with_scalar(
  priv_key : PrivateKey,
  e_bytes : Bytes,
  k_sc : U256,
) -> (Bytes, Bytes)? {
  if !sn_is_valid_nonzero(k_sc) {
    return None
  }
  let pt = scalar_mul_base(k_sc)
  if pt.is_inf {
    return None
  }
  let e = sn_reduce_u256(u256_from_be_view(e_bytes[:]))
  let x1_n = sn_reduce_u256(pt.x)
  let r = sn_add(e, x1_n)
  if u256_is_zero(r) {
    return None
  }
  // Check r + k != n  <=>  (r + k) mod n != 0
  if u256_is_zero(sn_add(r, k_sc)) {
    return None
  }
  let one_plus_d = sn_add(u256_one(), priv_key.d)
  let inv = sn_inv(one_plus_d)
  let rd = sn_mul(r, priv_key.d)
  let k_minus_rd = sn_sub(k_sc, rd)
  let s = sn_mul(inv, k_minus_rd)
  if u256_is_zero(s) {
    return None
  }
  Some((u256_to_be_bytes(r), u256_to_be_bytes(s)))
}

///|
/// Signs `(id, msg)` with an explicit 32-byte nonce `k` (GB/T 32918.2).
/// Returns `(r, s)` as 32-byte big-endian integers.
pub fn sign_with_k(
  priv_key : PrivateKey,
  id : Bytes,
  msg : Bytes,
  k : Bytes,
) -> (Bytes, Bytes) raise Sm2Error {
  if k.length() != 32 {
    raise InvalidLength(k.length())
  }
  let k_sc = u256_from_be_view(k[:])
  let e_bytes = compute_digest(id, priv_key.public_key(), msg)
  match sign_digest_with_scalar(priv_key, e_bytes, k_sc) {
    Some(sig) => sig
    None => raise InvalidSignature
  }
}

///|
/// Deterministically signs `(id, msg)` using RFC 6979-style HMAC-SM3 nonce generation.
/// Returns `(r, s)` as 32-byte big-endian integers.
pub fn sign_deterministic(
  priv_key : PrivateKey,
  id : Bytes,
  msg : Bytes,
) -> (Bytes, Bytes) raise Sm2Error {
  let e_bytes = compute_digest(id, priv_key.public_key(), msg)
  let x_bytes = priv_key.to_bytes()
  let mut v = Bytes::from_array(FixedArray::make(32, b'\x01'))
  let mut k = Bytes::from_array(FixedArray::make(32, b'\x00'))
  let zero_byte : Bytes = b"\x00"
  let one_byte : Bytes = b"\x01"

  k = @sm3.hmac_sm3_parts(k, [v[:], zero_byte[:], x_bytes[:], e_bytes[:]])
  v = @sm3.hmac_sm3(k, v)
  k = @sm3.hmac_sm3_parts(k, [v[:], one_byte[:], x_bytes[:], e_bytes[:]])
  v = @sm3.hmac_sm3(k, v)

  for attempt = 0; attempt < 1024; attempt = attempt + 1 {
    v = @sm3.hmac_sm3(k, v)
    let k_sc = u256_from_be_view(v[:])
    match sign_digest_with_scalar(priv_key, e_bytes, k_sc) {
      Some(sig) => return sig
      None => {
        k = @sm3.hmac_sm3_parts(k, [v[:], zero_byte[:]])
        v = @sm3.hmac_sm3(k, v)
      }
    }
  }
  raise InvalidSignature
}

// ============================================================================
// ASN.1 DER Helpers (Signatures & SM2Cipher)
// ============================================================================

///|
fn append_der_length(buf : Array[Byte], len : Int32) -> Unit {
  if len < 0x80 {
    buf.push(len.to_byte())
  } else if len <= 0xFF {
    buf.push(b'\x81')
    buf.push(len.to_byte())
  } else if len <= 0xFFFF {
    buf.push(b'\x82')
    buf.push(((len >> 8) & 0xFF).to_byte())
    buf.push((len & 0xFF).to_byte())
  } else if len <= 0xFFFFFF {
    buf.push(b'\x83')
    buf.push(((len >> 16) & 0xFF).to_byte())
    buf.push(((len >> 8) & 0xFF).to_byte())
    buf.push((len & 0xFF).to_byte())
  } else {
    buf.push(b'\x84')
    buf.push(((len >> 24) & 0xFF).to_byte())
    buf.push(((len >> 16) & 0xFF).to_byte())
    buf.push(((len >> 8) & 0xFF).to_byte())
    buf.push((len & 0xFF).to_byte())
  }
}

///|
fn append_der_uint(buf : Array[Byte], val : Bytes) -> Unit {
  if val.length() == 0 {
    buf.push(b'\x02')
    buf.push(b'\x01')
    buf.push(b'\x00')
    return
  }
  let mut start = 0
  while start < val.length() - 1 && val[start] == b'\x00' {
    start = start + 1
  }
  let need_pad = (val[start].to_int() & 0x80) != 0
  let body_len = val.length() - start + (if need_pad { 1 } else { 0 })
  buf.push(b'\x02')
  append_der_length(buf, body_len)
  if need_pad {
    buf.push(b'\x00')
  }
  for i = start; i < val.length(); i = i + 1 {
    buf.push(val[i])
  }
}

///|
fn append_der_octet_string(buf : Array[Byte], data : BytesView) -> Unit {
  buf.push(b'\x04')
  append_der_length(buf, data.length())
  for i = 0; i < data.length(); i = i + 1 {
    buf.push(data[i])
  }
}

///|
fn array_to_bytes(arr : Array[Byte]) -> Bytes {
  let out = FixedArray::make(arr.length(), b'\x00')
  for i = 0; i < arr.length(); i = i + 1 {
    out[i] = arr[i]
  }
  Bytes::from_array(out)
}

///|
/// Strictly parses a DER definite length starting at `pos`.
/// Returns `Some((length, next_pos))` or `None` on malformed/non-canonical DER.
fn parse_der_length(data : Bytes, pos : Int32) -> (Int32, Int32)? {
  if pos >= data.length() {
    return None
  }
  let first = data[pos].to_int()
  if first < 0x80 {
    let next = pos + 1
    if first > data.length() - next {
      return None
    }
    return Some((first, next))
  }
  let num_bytes = first & 0x7F
  if num_bytes == 0 || num_bytes > 4 {
    return None
  }
  let next = pos + 1 + num_bytes
  if next > data.length() {
    return None
  }
  // Minimal DER length: first length byte must not be 0x00; also reject signed 32-bit overflow
  if data[pos + 1] == b'\x00' ||
    (num_bytes == 4 && (data[pos + 1].to_int() & 0x80) != 0) {
    return None
  }
  let mut len = 0
  for i = 0; i < num_bytes; i = i + 1 {
    len = (len << 8) | data[pos + 1 + i].to_int()
  }
  // Long form must not be used for lengths < 128, and length must fit in remaining data
  if len < 0x80 || len > data.length() - next {
    return None
  }
  Some((len, next))
}

///|
/// Strictly parses a DER positive INTEGER into a 32-byte big-endian `Bytes`.
fn parse_der_uint32(data : Bytes, pos : Int32) -> (Bytes, Int32)? {
  if pos >= data.length() || data[pos] != b'\x02' {
    return None
  }
  let (len, start) = match parse_der_length(data, pos + 1) {
    Some(v) => v
    None => return None
  }
  if len <= 0 || start + len > data.length() {
    return None
  }
  // Reject negative integers (MSB set)
  if (data[start].to_int() & 0x80) != 0 {
    return None
  }
  // Minimal DER integer check: leading 0x00 only allowed if followed by byte with MSB set
  let mut val_start = start
  let mut val_len = len
  if data[start] == b'\x00' {
    if len == 1 {
      // Single 0x00 represents integer 0
    } else if (data[start + 1].to_int() & 0x80) == 0 {
      return None
    } else {
      val_start = start + 1
      val_len = len - 1
    }
  }
  if val_len > 32 {
    return None
  }
  let out = FixedArray::make(32, b'\x00')
  let pad = 32 - val_len
  for i = 0; i < val_len; i = i + 1 {
    out[pad + i] = data[val_start + i]
  }
  Some((Bytes::from_array(out), start + len))
}

///|
/// Encodes `(r, s)` as an ASN.1 DER `SEQUENCE { INTEGER r, INTEGER s }`.
pub fn encode_sig_der(r : Bytes, s : Bytes) -> Bytes {
  let body : Array[Byte] = []
  append_der_uint(body, r)
  append_der_uint(body, s)
  let out : Array[Byte] = []
  out.push(b'\x30')
  append_der_length(out, body.length())
  for i = 0; i < body.length(); i = i + 1 {
    out.push(body[i])
  }
  array_to_bytes(out)
}

///|
/// Strictly decodes an ASN.1 DER SM2 signature into 32-byte big-endian `(r, s)`.
pub fn decode_sig_der(der : Bytes) -> (Bytes, Bytes) raise Sm2Error {
  if der.length() < 6 || der[0] != b'\x30' {
    raise InvalidSignature
  }
  let (seq_len, pos1) = match parse_der_length(der, 1) {
    Some(v) => v
    None => raise InvalidSignature
  }
  if pos1 + seq_len != der.length() {
    raise InvalidSignature
  }
  let (r, pos2) = match parse_der_uint32(der, pos1) {
    Some(v) => v
    None => raise InvalidSignature
  }
  let (s, pos3) = match parse_der_uint32(der, pos2) {
    Some(v) => v
    None => raise InvalidSignature
  }
  if pos3 != der.length() {
    raise InvalidSignature
  }
  (r, s)
}

///|
/// Deterministically signs `(id, msg)` and returns the ASN.1 DER-encoded signature.
pub fn sign_der(
  priv_key : PrivateKey,
  id : Bytes,
  msg : Bytes,
) -> Bytes raise Sm2Error {
  let (r, s) = sign_deterministic(priv_key, id, msg)
  encode_sig_der(r, s)
}

///|
/// Verifies a raw `(r, s)` SM2 signature against `(pubkey, id, msg)`.
pub fn verify_raw(
  pubkey : PublicKey,
  id : Bytes,
  msg : Bytes,
  r : Bytes,
  s : Bytes,
) -> Bool {
  if !pubkey.is_valid() || r.length() != 32 || s.length() != 32 {
    return false
  }
  let r_sc = u256_from_be_view(r[:])
  let s_sc = u256_from_be_view(s[:])
  if !sn_is_valid_nonzero(r_sc) || !sn_is_valid_nonzero(s_sc) {
    return false
  }
  let e_bytes = compute_digest(id, pubkey, msg)
  let e = sn_reduce_u256(u256_from_be_view(e_bytes[:]))
  let t = sn_add(r_sc, s_sc)
  if u256_is_zero(t) {
    return false
  }
  let pt = scalar_mul_add_base(s_sc, t, pubkey.to_affine())
  if pt.is_inf {
    return false
  }
  let x1_n = sn_reduce_u256(pt.x)
  let r_calc = sn_add(e, x1_n)
  u256_eq(r_calc, r_sc)
}

///|
/// Verifies an ASN.1 DER-encoded SM2 signature against `(pubkey, id, msg)`.
pub fn verify_der(
  pubkey : PublicKey,
  id : Bytes,
  msg : Bytes,
  der_sig : Bytes,
) -> Bool {
  let (r, s) = decode_sig_der(der_sig) catch { _ => return false }
  verify_raw(pubkey, id, msg, r, s)
}

// ============================================================================
// Part 3: SM2 Key Exchange Protocol (GB/T 32918.3-2016)
// ============================================================================

///|
/// Computes x_bar = 2^127 + (x & (2^127 - 1)) per GB/T 32918.3 (w = 127).
fn compute_x_bar(x : U256) -> U256 {
  let limbs = FixedArray::make(8, 0U)
  limbs[0] = x.limbs[0]
  limbs[1] = x.limbs[1]
  limbs[2] = x.limbs[2]
  limbs[3] = (x.limbs[3] & 0x7FFFFFFFU) | 0x80000000U
  { limbs, }
}

///|
fn derive_ke_result(
  shared_pt : AffinePoint,
  za : Bytes,
  zb : Bytes,
  ra : PublicKey,
  rb : PublicKey,
  klen : Int32,
) -> KeyExchangeResult {
  let xu = u256_to_be_bytes(shared_pt.x)
  let yu = u256_to_be_bytes(shared_pt.y)
  // K = KDF(x_U || y_U || Z_A || Z_B, klen)
  let kdf_in = FixedArray::make(128, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    kdf_in[i] = xu[i]
    kdf_in[32 + i] = yu[i]
    kdf_in[64 + i] = za[i]
    kdf_in[96 + i] = zb[i]
  }
  let shared_key = @sm3.kdf_sm3(Bytes::from_array(kdf_in), klen)

  // H_inner = SM3(x_U || Z_A || Z_B || x_1 || y_1 || x_2 || y_2)
  let inner = @sm3.Sm3::new()
  inner.update(xu)
  inner.update(za)
  inner.update(zb)
  inner.update(ra.x_bytes())
  inner.update(ra.y_bytes())
  inner.update(rb.x_bytes())
  inner.update(rb.y_bytes())
  let h_inner = inner.finalize()

  // S1 / S_B = SM3(0x02 || y_U || H_inner)
  let h1 = @sm3.Sm3::new()
  h1.update(b"\x02")
  h1.update(yu)
  h1.update(h_inner)
  let s1 = h1.finalize()

  // S2 / S_A = SM3(0x03 || y_U || H_inner)
  let h2 = @sm3.Sm3::new()
  h2.update(b"\x03")
  h2.update(yu)
  h2.update(h_inner)
  let s2 = h2.finalize()

  { shared_key, s1, s2, }
}

///|
/// GB/T 32918.3 SM2 Key Exchange — Initiator (User A) side.
/// Returns `KeyExchangeResult { shared_key, s1 (tag 0x02), s2 (tag 0x03) }`.
pub fn key_exchange_initiator(
  id_a : Bytes,
  priv_a : PrivateKey,
  eph_priv_a : PrivateKey,
  id_b : Bytes,
  pub_b : PublicKey,
  eph_pub_b : PublicKey,
  klen : Int32,
) -> KeyExchangeResult raise Sm2Error {
  if klen <= 0 {
    raise InvalidLength(klen)
  }
  if !pub_b.is_valid() || !eph_pub_b.is_valid() {
    raise KeyExchangeFailed
  }
  let pub_a = priv_a.public_key()
  let ra = eph_priv_a.public_key()
  let x1_bar = compute_x_bar(ra.x)
  let t_a = sn_add(priv_a.d, sn_mul(x1_bar, eph_priv_a.d))
  let x2_bar = compute_x_bar(eph_pub_b.x)

  // U = [h * t_A](P_B + [x2_bar] R_B), h = 1
  let x2_rb = scalar_mul(x2_bar, eph_pub_b.to_affine())
  if x2_rb.is_inf {
    raise KeyExchangeFailed
  }
  let pb_plus = jac_to_affine(
    jac_add(jac_from_affine(pub_b.to_affine()), jac_from_affine(x2_rb)),
  )
  if pb_plus.is_inf {
    raise KeyExchangeFailed
  }
  let u = scalar_mul(t_a, pb_plus)
  if u.is_inf {
    raise KeyExchangeFailed
  }
  let za = compute_za(id_a, pub_a)
  let zb = compute_za(id_b, pub_b)
  derive_ke_result(u, za, zb, ra, eph_pub_b, klen)
}

///|
/// GB/T 32918.3 SM2 Key Exchange — Responder (User B) side.
/// Returns `KeyExchangeResult { shared_key, s1 (tag 0x02 / S_B), s2 (tag 0x03 / S_2) }`.
pub fn key_exchange_responder(
  id_b : Bytes,
  priv_b : PrivateKey,
  eph_priv_b : PrivateKey,
  id_a : Bytes,
  pub_a : PublicKey,
  eph_pub_a : PublicKey,
  klen : Int32,
) -> KeyExchangeResult raise Sm2Error {
  if klen <= 0 {
    raise InvalidLength(klen)
  }
  if !pub_a.is_valid() || !eph_pub_a.is_valid() {
    raise KeyExchangeFailed
  }
  let pub_b = priv_b.public_key()
  let rb = eph_priv_b.public_key()
  let x2_bar = compute_x_bar(rb.x)
  let t_b = sn_add(priv_b.d, sn_mul(x2_bar, eph_priv_b.d))
  let x1_bar = compute_x_bar(eph_pub_a.x)

  // V = [h * t_B](P_A + [x1_bar] R_A), h = 1
  let x1_ra = scalar_mul(x1_bar, eph_pub_a.to_affine())
  if x1_ra.is_inf {
    raise KeyExchangeFailed
  }
  let pa_plus = jac_to_affine(
    jac_add(jac_from_affine(pub_a.to_affine()), jac_from_affine(x1_ra)),
  )
  if pa_plus.is_inf {
    raise KeyExchangeFailed
  }
  let v = scalar_mul(t_b, pa_plus)
  if v.is_inf {
    raise KeyExchangeFailed
  }
  let za = compute_za(id_a, pub_a)
  let zb = compute_za(id_b, pub_b)
  derive_ke_result(v, za, zb, eph_pub_a, rb, klen)
}

// ============================================================================
// Part 4: SM2 Public Key Encryption & Decryption (GB/T 32918.4-2016)
// ============================================================================

///|
fn bytes_is_all_zero(data : Bytes) -> Bool {
  let mut acc = 0U
  for i = 0; i < data.length(); i = i + 1 {
    acc = acc | data[i].to_uint()
  }
  acc == 0U
}

///|
fn encrypt_core(
  pubkey : PublicKey,
  plaintext : Bytes,
  k_sc : U256,
) -> (Bytes, Bytes, Bytes, Bytes) raise Sm2Error {
  if !pubkey.is_valid() {
    raise InvalidPublicKey
  }
  if !sn_is_valid_nonzero(k_sc) {
    raise InvalidPrivateKey
  }
  let c1_pt = scalar_mul_base(k_sc)
  if c1_pt.is_inf {
    raise InvalidCiphertext
  }
  let s_pt = scalar_mul(k_sc, pubkey.to_affine())
  if s_pt.is_inf {
    raise InvalidPublicKey
  }
  let x2_bytes = u256_to_be_bytes(s_pt.x)
  let y2_bytes = u256_to_be_bytes(s_pt.y)
  let kdf_seed = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    kdf_seed[i] = x2_bytes[i]
    kdf_seed[32 + i] = y2_bytes[i]
  }
  let t = @sm3.kdf_sm3(Bytes::from_array(kdf_seed), plaintext.length())
  if plaintext.length() > 0 && bytes_is_all_zero(t) {
    raise InvalidCiphertext
  }
  let c2_arr = FixedArray::make(plaintext.length(), b'\x00')
  for i = 0; i < plaintext.length(); i = i + 1 {
    c2_arr[i] = (plaintext[i].to_uint() ^ t[i].to_uint()).to_byte()
  }
  let h = @sm3.Sm3::new()
  h.update(x2_bytes)
  h.update(plaintext)
  h.update(y2_bytes)
  let c3 = h.finalize()
  (
    u256_to_be_bytes(c1_pt.x),
    u256_to_be_bytes(c1_pt.y),
    c3,
    Bytes::from_array(c2_arr),
  )
}

///|
/// Encrypts `plaintext` using an explicit 32-byte ephemeral scalar `k`.
/// Returns `0x04 || C1(64) || C3(32) || C2(plaintext.length())`.
pub fn encrypt_with_k(
  pubkey : PublicKey,
  plaintext : Bytes,
  k : Bytes,
) -> Bytes raise Sm2Error {
  if k.length() != 32 {
    raise InvalidLength(k.length())
  }
  let k_sc = u256_from_be_view(k[:])
  let (x1, y1, c3, c2) = encrypt_core(pubkey, plaintext, k_sc)
  let out = FixedArray::make(97 + c2.length(), b'\x00')
  out[0] = b'\x04'
  for i = 0; i < 32; i = i + 1 {
    out[1 + i] = x1[i]
    out[33 + i] = y1[i]
    out[65 + i] = c3[i]
  }
  for i = 0; i < c2.length(); i = i + 1 {
    out[97 + i] = c2[i]
  }
  Bytes::from_array(out)
}

///|
fn encrypt_components_with_seed(
  pubkey : PublicKey,
  plaintext : Bytes,
  seed : Bytes,
) -> (Bytes, Bytes, Bytes, Bytes) raise Sm2Error {
  if !pubkey.is_valid() {
    raise InvalidPublicKey
  }
  let pt_hash = @sm3.sm3(plaintext)
  let pk_xy = pubkey.to_xy_bytes()
  let ctr_buf = FixedArray::make(4, b'\x00')
  let mut ctr : UInt32 = 0U
  for attempt = 0; attempt < 1024; attempt = attempt + 1 {
    write_be32(ctr_buf, 0, ctr)
    let h = @sm3.Sm3::new()
    h.update(b"SM2-ENC-K-V1")
    h.update(seed)
    h.update(pk_xy)
    h.update(pt_hash)
    h.update(Bytes::from_array(ctr_buf))
    let k_bytes = h.finalize()
    let k_sc = u256_from_be_view(k_bytes[:])
    if sn_is_valid_nonzero(k_sc) {
      let res = Some(encrypt_core(pubkey, plaintext, k_sc)) catch { _ => None }
      match res {
        Some(parts) => return parts
        None => ()
      }
    }
    ctr = ctr + 1U
  }
  raise InvalidCiphertext
}

///|
/// Encrypts `plaintext` with a seed-derived ephemeral scalar in C1C3C2 format:
/// `0x04 || C1(64) || C3(32) || C2(len)`.
pub fn encrypt_c1c3c2(
  pubkey : PublicKey,
  plaintext : Bytes,
  seed : Bytes,
) -> Bytes raise Sm2Error {
  let (x1, y1, c3, c2) = encrypt_components_with_seed(pubkey, plaintext, seed)
  let out = FixedArray::make(97 + c2.length(), b'\x00')
  out[0] = b'\x04'
  for i = 0; i < 32; i = i + 1 {
    out[1 + i] = x1[i]
    out[33 + i] = y1[i]
    out[65 + i] = c3[i]
  }
  for i = 0; i < c2.length(); i = i + 1 {
    out[97 + i] = c2[i]
  }
  Bytes::from_array(out)
}

///|
fn decrypt_core(
  priv_key : PrivateKey,
  c1 : PublicKey,
  c3 : Bytes,
  c2 : BytesView,
) -> Bytes raise Sm2Error {
  let s_pt = scalar_mul(priv_key.d, c1.to_affine())
  if s_pt.is_inf {
    raise DecryptionFailed
  }
  let x2_bytes = u256_to_be_bytes(s_pt.x)
  let y2_bytes = u256_to_be_bytes(s_pt.y)
  let kdf_seed = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    kdf_seed[i] = x2_bytes[i]
    kdf_seed[32 + i] = y2_bytes[i]
  }
  let mlen = c2.length()
  let t = @sm3.kdf_sm3(Bytes::from_array(kdf_seed), mlen)
  if mlen > 0 && bytes_is_all_zero(t) {
    raise DecryptionFailed
  }
  let pt_arr = FixedArray::make(mlen, b'\x00')
  for i = 0; i < mlen; i = i + 1 {
    pt_arr[i] = (c2[i].to_uint() ^ t[i].to_uint()).to_byte()
  }
  let plaintext = Bytes::from_array(pt_arr)
  let h = @sm3.Sm3::new()
  h.update(x2_bytes)
  h.update(plaintext)
  h.update(y2_bytes)
  let u = h.finalize()
  if !@ct.ct_eq(u, c3) {
    raise DecryptionFailed
  }
  plaintext
}

///|
fn bytes_from_view(v : BytesView) -> Bytes {
  let out = FixedArray::make(v.length(), b'\x00')
  for i = 0; i < v.length(); i = i + 1 {
    out[i] = v[i]
  }
  Bytes::from_array(out)
}

///|
/// Decrypts a C1C3C2 SM2 ciphertext (accepts both `0x04`-prefixed and unprefixed C1).
/// Validates C1 on curve and verifies C3 in constant time using `@ct.ct_eq`.
pub fn decrypt_c1c3c2(
  priv_key : PrivateKey,
  ciphertext : Bytes,
) -> Bytes raise Sm2Error {
  if ciphertext.length() < 96 {
    raise InvalidCiphertext
  }
  // Try 0x04-prefixed C1 first when length >= 97 and first byte is 0x04;
  // fall back to unprefixed C1 in case an unprefixed X coordinate begins with 0x04.
  if ciphertext.length() >= 97 && ciphertext[0] == b'\x04' {
    let prefixed_c1 = Some(
      PublicKey::from_bytes(bytes_from_view(ciphertext[0:65])),
    ) catch {
      _ => None
    }
    match prefixed_c1 {
      Some(c1) => {
        let c3 = bytes_from_view(ciphertext[65:97])
        let c2 = ciphertext[97:]
        return decrypt_core(priv_key, c1, c3, c2)
      }
      None => ()
    }
  }
  let c1 = PublicKey::from_bytes(bytes_from_view(ciphertext[0:64])) catch {
    _ => raise InvalidCiphertext
  }
  let c3 = bytes_from_view(ciphertext[64:96])
  let c2 = ciphertext[96:]
  decrypt_core(priv_key, c1, c3, c2)
}

///|
/// Encrypts `plaintext` into strict ASN.1 DER `SM2Cipher`:
/// `SEQUENCE { x INTEGER, y INTEGER, hash OCTET STRING(32), cipher OCTET STRING }`.
pub fn encrypt_asn1(
  pubkey : PublicKey,
  plaintext : Bytes,
  seed : Bytes,
) -> Bytes raise Sm2Error {
  let (x1, y1, c3, c2) = encrypt_components_with_seed(pubkey, plaintext, seed)
  let body : Array[Byte] = []
  append_der_uint(body, x1)
  append_der_uint(body, y1)
  append_der_octet_string(body, c3[:])
  append_der_octet_string(body, c2[:])
  let out : Array[Byte] = []
  out.push(b'\x30')
  append_der_length(out, body.length())
  for i = 0; i < body.length(); i = i + 1 {
    out.push(body[i])
  }
  array_to_bytes(out)
}

///|
/// Strictly decodes and decrypts an ASN.1 DER `SM2Cipher`.
/// Verifies C1 on curve and validates C3 in constant time using `@ct.ct_eq`.
pub fn decrypt_asn1(
  priv_key : PrivateKey,
  der_cipher : Bytes,
) -> Bytes raise Sm2Error {
  if der_cipher.length() < 8 || der_cipher[0] != b'\x30' {
    raise InvalidCiphertext
  }
  let (seq_len, pos1) = match parse_der_length(der_cipher, 1) {
    Some(v) => v
    None => raise InvalidCiphertext
  }
  if pos1 + seq_len != der_cipher.length() {
    raise InvalidCiphertext
  }
  let (x1_bytes, pos2) = match parse_der_uint32(der_cipher, pos1) {
    Some(v) => v
    None => raise InvalidCiphertext
  }
  let (y1_bytes, pos3) = match parse_der_uint32(der_cipher, pos2) {
    Some(v) => v
    None => raise InvalidCiphertext
  }
  // Parse HASH OCTET STRING (must be exactly 32 bytes)
  if pos3 >= der_cipher.length() || der_cipher[pos3] != b'\x04' {
    raise InvalidCiphertext
  }
  let (c3_len, c3_start) = match parse_der_length(der_cipher, pos3 + 1) {
    Some(v) => v
    None => raise InvalidCiphertext
  }
  if c3_len != 32 || c3_start + 32 > der_cipher.length() {
    raise InvalidCiphertext
  }
  let c3 = bytes_from_view(der_cipher[c3_start:c3_start + 32])
  let pos4 = c3_start + 32
  // Parse CipherText OCTET STRING
  if pos4 >= der_cipher.length() || der_cipher[pos4] != b'\x04' {
    raise InvalidCiphertext
  }
  let (c2_len, c2_start) = match parse_der_length(der_cipher, pos4 + 1) {
    Some(v) => v
    None => raise InvalidCiphertext
  }
  if c2_start + c2_len != der_cipher.length() {
    raise InvalidCiphertext
  }
  let c2 = der_cipher[c2_start:c2_start + c2_len]

  // Validate C1 on SM2 curve
  let xy = FixedArray::make(64, b'\x00')
  for i = 0; i < 32; i = i + 1 {
    xy[i] = x1_bytes[i]
    xy[32 + i] = y1_bytes[i]
  }
  let c1 = PublicKey::from_bytes(Bytes::from_array(xy)) catch {
    _ => raise InvalidCiphertext
  }
  decrypt_core(priv_key, c1, c3, c2)
}
