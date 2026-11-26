///|
/// GB/T 38635.1-2020 §5.4.2–5.4.3 SM9 auxiliary hash, KDF, MAC, H1, and H2
/// adapter strictly delegating all SM3 compression to the shared
/// `CoolrfulDARkness/moontlcp/crypto/sm3` core and constant-time equality to
/// `CoolrfulDARkness/moontlcp/crypto/ct`.

///|
/// Streaming SM3 hasher wrapper delegating directly to `crypto/sm3`.
pub struct Sm3 {
  priv inner : @core_sm3.Sm3
}

///|
fn read_be_u64_view(buf : BytesView, off : Int32) -> UInt64 {
  (buf[off].to_uint64() << 56) |
  (buf[off + 1].to_uint64() << 48) |
  (buf[off + 2].to_uint64() << 40) |
  (buf[off + 3].to_uint64() << 32) |
  (buf[off + 4].to_uint64() << 24) |
  (buf[off + 5].to_uint64() << 16) |
  (buf[off + 6].to_uint64() << 8) |
  buf[off + 7].to_uint64()
}

///|
fn write_be_u64(out : FixedArray[Byte], off : Int32, v : UInt64) -> Unit {
  out[off] = (v >> 56).to_byte()
  out[off + 1] = (v >> 48).to_byte()
  out[off + 2] = (v >> 40).to_byte()
  out[off + 3] = (v >> 32).to_byte()
  out[off + 4] = (v >> 24).to_byte()
  out[off + 5] = (v >> 16).to_byte()
  out[off + 6] = (v >> 8).to_byte()
  out[off + 7] = v.to_byte()
}

///|
/// Creates a new SM3 hasher initialized to the standard GB/T 32905 IV.
pub fn Sm3::new() -> Sm3 {
  { inner: @core_sm3.Sm3::new(), }
}

///|
/// Resets the SM3 hasher back to its initial state.
pub fn Sm3::reset(self : Sm3) -> Unit {
  self.inner.reset()
}

///|
fn Sm3::clone(self : Sm3) -> Sm3 {
  { inner: self.inner.clone(), }
}

///|
/// Absorbs a single byte into the SM3 state.
pub fn Sm3::update_byte(self : Sm3, b : Byte) -> Unit {
  self.inner.update_byte(b)
}

///|
/// Absorbs a byte slice into the SM3 state.
pub fn Sm3::update(self : Sm3, data : BytesView) -> Unit {
  self.inner.update_view(data)
}

///|
fn Sm3::update_be_u32(self : Sm3, v : UInt32) -> Unit {
  self.update_byte((v >> 24).to_byte())
  self.update_byte((v >> 16).to_byte())
  self.update_byte((v >> 8).to_byte())
  self.update_byte(v.to_byte())
}

///|
/// Finalizes the SM3 digest and returns the 32-byte hash without mutating `self`.
pub fn Sm3::finalize(self : Sm3) -> Bytes {
  self.inner.finalize()
}

///|
/// Computes the 32-byte SM3 digest of `data` via shared `crypto/sm3`.
pub fn hash(data : BytesView) -> Bytes {
  @core_sm3.sm3_view(data)
}

///|
/// Computes the 64-character lowercase hex SM3 digest of `data`.
pub fn hash_hex(data : BytesView) -> String {
  bytes_to_hex(hash(data))
}

///|
/// Key derivation function `KDF(Z, klen)` (GB/T 38635.1-2020 §5.4.3).
/// `klen` is in bytes; returns empty `Bytes` if `klen <= 0`.
pub fn kdf(z : BytesView, klen : Int32) -> Bytes {
  if klen <= 0 {
    return b""
  }
  let base = Sm3::new()
  base.update(z)
  let out : FixedArray[Byte] = FixedArray::make(klen, b'\x00')
  let mut offset = 0
  let mut ct : UInt32 = 1U
  while offset < klen {
    let h = base.clone()
    h.update_be_u32(ct)
    let block = h.finalize()
    let take = if klen - offset < 32 { klen - offset } else { 32 }
    for i = 0; i < take; i = i + 1 {
      out[offset + i] = block[i]
    }
    offset = offset + take
    ct = ct + 1U
  }
  Bytes::makei(klen, fn(i) { out[i] })
}

///|
/// Message authentication code `MAC(K2, C2) = SM3(C2 || K2)` (GB/T 38635.4-2020).
pub fn mac(k2 : BytesView, c2 : BytesView) -> Bytes {
  let hasher = Sm3::new()
  hasher.update(c2)
  hasher.update(k2)
  hasher.finalize()
}

///|
/// Auxiliary hash-expansion function `Hv` returning `out_len` bytes of
/// `SM3(tag || Z || ct)` for `ct = 1, 2, ...` (GB/T 38635.1-2020 §5.4.2).
pub fn hv_bytes(tag : Byte, z : BytesView, out_len : Int32) -> Bytes {
  if out_len <= 0 {
    return b""
  }
  let base = Sm3::new()
  base.update_byte(tag)
  base.update(z)
  let out : FixedArray[Byte] = FixedArray::make(out_len, b'\x00')
  let mut offset = 0
  let mut ct : UInt32 = 1U
  while offset < out_len {
    let h = base.clone()
    h.update_be_u32(ct)
    let block = h.finalize()
    let take = if out_len - offset < 32 { out_len - offset } else { 32 }
    for i = 0; i < take; i = i + 1 {
      out[offset + i] = block[i]
    }
    offset = offset + take
    ct = ct + 1U
  }
  Bytes::makei(out_len, fn(i) { out[i] })
}

///|
/// Computes the 40-byte raw expansion `Ha` for SM9 `H1` (`tag = 0x01`).
pub fn h1_hash40(z : BytesView) -> Bytes {
  hv_bytes(b'\x01', z, 40)
}

///|
/// Computes the 40-byte raw expansion `Ha` for SM9 `H2` (`tag = 0x02`).
pub fn h2_hash40(z : BytesView) -> Bytes {
  hv_bytes(b'\x02', z, 40)
}

///|
/// Branchless unsigned 64-bit less-than returning `1UL` if `a < b`, else `0UL`.
fn lt_u64(a : UInt64, b : UInt64) -> UInt64 {
  ((a.lnot() & b) | ((a ^ b).lnot() & (a - b))) >> 63
}

///|
/// Constant-time exact big-integer reduction: `(ha mod (n - 1)) + 1`
/// where `ha` is 40-byte big-endian unsigned integer and `n_be` is 32-byte big-endian (`n > 1`).
fn reduce_ha40_mod_n_minus_1_plus_1(ha : Bytes, n_be : BytesView) -> Bytes {
  if n_be.length() != 32 {
    abort("sm9/hash: n_be must be 32 bytes")
  }
  let n3 = read_be_u64_view(n_be, 0)
  let n2 = read_be_u64_view(n_be, 8)
  let n1 = read_be_u64_view(n_be, 16)
  let n0 = read_be_u64_view(n_be, 24)
  if n3 == 0UL && n2 == 0UL && n1 == 0UL && n0 <= 1UL {
    abort("sm9/hash: group order n must be greater than 1")
  }
  // m = n - 1 (256-bit little-endian limbs m0..m3)
  let m0 = n0 - 1UL
  let bm0 = lt_u64(n0, 1UL)
  let m1 = n1 - bm0
  let bm1 = lt_u64(n1, bm0)
  let m2 = n2 - bm1
  let bm2 = lt_u64(n2, bm1)
  let m3 = n3 - bm2
  // 257-bit remainder (r4, r3, r2, r1, r0), processing 320 bits of ha MSB-first.
  let mut r0 = 0UL
  let mut r1 = 0UL
  let mut r2 = 0UL
  let mut r3 = 0UL
  let mut r4 = 0UL
  for byte_idx = 0; byte_idx < 40; byte_idx = byte_idx + 1 {
    let b = ha[byte_idx].to_int()
    for shift = 7; shift >= 0; shift = shift - 1 {
      let bit = ((b >> shift) & 1).to_uint64()
      r4 = (r4 << 1) | (r3 >> 63)
      r3 = (r3 << 1) | (r2 >> 63)
      r2 = (r2 << 1) | (r1 >> 63)
      r1 = (r1 << 1) | (r0 >> 63)
      r0 = (r0 << 1) | bit
      // Trial subtraction: t = r - m
      let t0 = r0 - m0
      let b0 = lt_u64(r0, m0)
      let t1_a = r1 - m1
      let b1_a = lt_u64(r1, m1)
      let t1 = t1_a - b0
      let b1 = b1_a | lt_u64(t1_a, b0)
      let t2_a = r2 - m2
      let b2_a = lt_u64(r2, m2)
      let t2 = t2_a - b1
      let b2 = b2_a | lt_u64(t2_a, b1)
      let t3_a = r3 - m3
      let b3_a = lt_u64(r3, m3)
      let t3 = t3_a - b2
      let b3 = b3_a | lt_u64(t3_a, b2)
      let t4 = r4 - b3
      let underflow = lt_u64(r4, b3)
      // Select r if underflow == 1, else t (constant-time)
      let mask = 0UL - underflow
      r0 = t0 ^ ((t0 ^ r0) & mask)
      r1 = t1 ^ ((t1 ^ r1) & mask)
      r2 = t2 ^ ((t2 ^ r2) & mask)
      r3 = t3 ^ ((t3 ^ r3) & mask)
      r4 = t4 ^ ((t4 ^ r4) & mask)
    }
  }
  // h = r + 1
  let s0 = r0 + 1UL
  let c0 = lt_u64(s0, 1UL)
  let s1 = r1 + c0
  let c1 = lt_u64(s1, c0)
  let s2 = r2 + c1
  let c2 = lt_u64(s2, c1)
  let s3 = r3 + c2
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  write_be_u64(out, 0, s3)
  write_be_u64(out, 8, s2)
  write_be_u64(out, 16, s1)
  write_be_u64(out, 24, s0)
  Bytes::makei(32, fn(i) { out[i] })
}

///|
/// Cryptographic function `H1(Z, n)` returning a 32-byte big-endian scalar in `[1, n - 1]`
/// (GB/T 38635.1-2020 §5.4.2.2).
pub fn h1(z : BytesView, n_be : BytesView) -> Bytes {
  reduce_ha40_mod_n_minus_1_plus_1(h1_hash40(z), n_be)
}

///|
/// Cryptographic function `H2(Z, n)` returning a 32-byte big-endian scalar in `[1, n - 1]`
/// (GB/T 38635.1-2020 §5.4.2.3).
pub fn h2(z : BytesView, n_be : BytesView) -> Bytes {
  reduce_ha40_mod_n_minus_1_plus_1(h2_hash40(z), n_be)
}

///|
/// Constant-time byte slice equality check delegating to `crypto/ct`.
pub fn ct_eq_bytes(a : BytesView, b : BytesView) -> Bool {
  @ct.ct_eq_view(a, b)
}

///|
let hex_digits : FixedArray[Char] = [
  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
]

///|
/// Encodes bytes into a lowercase hexadecimal string.
pub fn bytes_to_hex(data : BytesView) -> String {
  let sb = StringBuilder(capacity=data.length() * 2)
  for i = 0; i < data.length(); i = i + 1 {
    let v = data[i].to_int()
    sb.write_char(hex_digits[(v >> 4) & 0xF])
    sb.write_char(hex_digits[v & 0xF])
  }
  sb.to_string()
}

///|
/// Decodes a hexadecimal string (case-insensitive, ignoring ASCII whitespace) into `Bytes`.
/// Returns `None` on invalid characters or odd number of hex digits.
pub fn hex_to_bytes(hex : String) -> Bytes? {
  let out : Array[Byte] = []
  let mut have_high = false
  let mut high = 0
  for c in hex {
    if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
      continue
    }
    let v = match c {
      '0'..<='9' => c.to_int() - '0'.to_int()
      'a'..<='f' => c.to_int() - 'a'.to_int() + 10
      'A'..<='F' => c.to_int() - 'A'.to_int() + 10
      _ => return None
    }
    if have_high {
      out.push(((high << 4) | v).to_byte())
      have_high = false
    } else {
      high = v
      have_high = true
    }
  }
  if have_high {
    return None
  }
  Some(Bytes::from_array(out))
}
