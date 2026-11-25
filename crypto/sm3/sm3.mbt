///|
/// GB/T 32905-2016 SM3 Cryptographic Hash Algorithm,
/// RFC 2104 HMAC-SM3, GM/T 0024-2023 TLCP PRF (P_SM3),
/// and GB/T 32918.4 SM2 KDF.

///|
pub const SM3_DIGEST_SIZE : Int = 32

///|
pub const SM3_BLOCK_SIZE : Int = 64

///|
fn rotl32(x : UInt, n : Int) -> UInt {
  let k = n & 31
  if k == 0 {
    x
  } else {
    (x << k) | (x >> (32 - k))
  }
}

///|
fn p0(x : UInt) -> UInt {
  x ^ rotl32(x, 9) ^ rotl32(x, 17)
}

///|
fn p1(x : UInt) -> UInt {
  x ^ rotl32(x, 15) ^ rotl32(x, 23)
}

///|
fn ff(x : UInt, y : UInt, z : UInt, j : Int) -> UInt {
  if j < 16 {
    x ^ y ^ z
  } else {
    (x & y) | (x & z) | (y & z)
  }
}

///|
fn gg(x : UInt, y : UInt, z : UInt, j : Int) -> UInt {
  if j < 16 {
    x ^ y ^ z
  } else {
    (x & y) | (x.lnot() & z)
  }
}

///|
fn read_be32_arr(buf : FixedArray[Byte], off : Int) -> UInt {
  (buf[off].to_uint() << 24) |
  (buf[off + 1].to_uint() << 16) |
  (buf[off + 2].to_uint() << 8) |
  buf[off + 3].to_uint()
}

///|
fn write_be32_arr(buf : FixedArray[Byte], off : Int, v : UInt) -> Unit {
  buf[off] = ((v >> 24) & 0xFFU).to_byte()
  buf[off + 1] = ((v >> 16) & 0xFFU).to_byte()
  buf[off + 2] = ((v >> 8) & 0xFFU).to_byte()
  buf[off + 3] = (v & 0xFFU).to_byte()
}

///|
/// Streaming SM3 hash state.
pub struct Sm3 {
  state : FixedArray[UInt]
  block : FixedArray[Byte]
  mut block_len : Int
  mut total_len : UInt64
}

///|
/// Creates a fresh SM3 hasher initialized with the GB/T 32905 IV.
pub fn Sm3::new() -> Sm3 {
  {
    state: [
      0x7380166FU, 0x4914B2B9U, 0x172442D7U, 0xDA8A0600U, 0xA96F30BCU, 0x163138AAU,
      0xE38DEE4DU, 0xB0FB0E4EU,
    ],
    block: FixedArray::make(64, b'\x00'),
    block_len: 0,
    total_len: 0UL,
  }
}

///|
/// Clones the current SM3 state (useful for rolling TLCP handshake transcript).
pub fn Sm3::clone(self : Sm3) -> Sm3 {
  let state = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    state[i] = self.state[i]
  }
  let block = FixedArray::make(64, b'\x00')
  for i = 0; i < 64; i = i + 1 {
    block[i] = self.block[i]
  }
  { state, block, block_len: self.block_len, total_len: self.total_len }
}

///|
fn Sm3::compress(self : Sm3) -> Unit {
  let w = FixedArray::make(68, 0U)
  let w1 = FixedArray::make(64, 0U)
  for i = 0; i < 16; i = i + 1 {
    w[i] = read_be32_arr(self.block, i * 4)
  }
  for j = 16; j < 68; j = j + 1 {
    w[j] = p1(w[j - 16] ^ w[j - 9] ^ rotl32(w[j - 3], 15)) ^
      rotl32(w[j - 13], 7) ^
      w[j - 6]
  }
  for j = 0; j < 64; j = j + 1 {
    w1[j] = w[j] ^ w[j + 4]
  }
  let mut a = self.state[0]
  let mut b = self.state[1]
  let mut c = self.state[2]
  let mut d = self.state[3]
  let mut e = self.state[4]
  let mut f = self.state[5]
  let mut g = self.state[6]
  let mut h = self.state[7]
  for j = 0; j < 64; j = j + 1 {
    let tj = if j < 16 { 0x79CC4519U } else { 0x7A879D8AU }
    let a12 = rotl32(a, 12)
    let ss1 = rotl32(a12 + e + rotl32(tj, j), 7)
    let ss2 = ss1 ^ a12
    let tt1 = ff(a, b, c, j) + d + ss2 + w1[j]
    let tt2 = gg(e, f, g, j) + h + ss1 + w[j]
    d = c
    c = rotl32(b, 9)
    b = a
    a = tt1
    h = g
    g = rotl32(f, 19)
    f = e
    e = p0(tt2)
  }
  self.state[0] = self.state[0] ^ a
  self.state[1] = self.state[1] ^ b
  self.state[2] = self.state[2] ^ c
  self.state[3] = self.state[3] ^ d
  self.state[4] = self.state[4] ^ e
  self.state[5] = self.state[5] ^ f
  self.state[6] = self.state[6] ^ g
  self.state[7] = self.state[7] ^ h
}

///|
/// Feeds a `BytesView` chunk into the SM3 hasher.
pub fn Sm3::update_view(self : Sm3, data : BytesView) -> Unit {
  let len = data.length()
  self.total_len = self.total_len + len.to_uint64()
  let mut pos = 0
  while pos < len {
    let take = if len - pos < 64 - self.block_len {
      len - pos
    } else {
      64 - self.block_len
    }
    for i = 0; i < take; i = i + 1 {
      self.block[self.block_len + i] = data[pos + i]
    }
    self.block_len = self.block_len + take
    pos = pos + take
    if self.block_len == 64 {
      self.compress()
      self.block_len = 0
    }
  }
}

///|
/// Feeds `Bytes` into the SM3 hasher.
pub fn Sm3::update(self : Sm3, data : Bytes) -> Unit {
  self.update_view(data[:])
}

///|
/// Finalizes a copy of the state and returns the 32-byte digest without mutating `self`.
pub fn Sm3::finalize(self : Sm3) -> Bytes {
  let copy = self.clone()
  let bit_len = copy.total_len << 3
  copy.block[copy.block_len] = b'\x80'
  copy.block_len = copy.block_len + 1
  if copy.block_len > 56 {
    while copy.block_len < 64 {
      copy.block[copy.block_len] = b'\x00'
      copy.block_len = copy.block_len + 1
    }
    copy.compress()
    copy.block_len = 0
  }
  while copy.block_len < 56 {
    copy.block[copy.block_len] = b'\x00'
    copy.block_len = copy.block_len + 1
  }
  let hi = (bit_len >> 32).to_uint()
  let lo = (bit_len & 0xFFFFFFFFUL).to_uint()
  write_be32_arr(copy.block, 56, hi)
  write_be32_arr(copy.block, 60, lo)
  copy.compress()
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    write_be32_arr(out, i * 4, copy.state[i])
  }
  Bytes::from_array(out)
}

///|
/// One-shot SM3 hash over `Bytes`.
pub fn sm3(data : Bytes) -> Bytes {
  let h = Sm3::new()
  h.update(data)
  h.finalize()
}

///|
/// One-shot SM3 hash over `BytesView`.
pub fn sm3_view(data : BytesView) -> Bytes {
  let h = Sm3::new()
  h.update_view(data)
  h.finalize()
}

///|
/// RFC 2104 HMAC-SM3 (block size 64 bytes, output 32 bytes).
pub fn hmac_sm3(key : Bytes, data : Bytes) -> Bytes {
  let k = if key.length() > SM3_BLOCK_SIZE { sm3(key) } else { key }
  let ipad = FixedArray::make(SM3_BLOCK_SIZE, b'\x36')
  let opad = FixedArray::make(SM3_BLOCK_SIZE, b'\x5c')
  for i = 0; i < k.length(); i = i + 1 {
    ipad[i] = (k[i].to_uint() ^ 0x36U).to_byte()
    opad[i] = (k[i].to_uint() ^ 0x5CU).to_byte()
  }
  let inner = Sm3::new()
  inner.update(Bytes::from_array(ipad))
  inner.update(data)
  let inner_digest = inner.finalize()
  let outer = Sm3::new()
  outer.update(Bytes::from_array(opad))
  outer.update(inner_digest)
  outer.finalize()
}

///|
/// HMAC-SM3 over multiple chunks (avoids extra concatenation allocations).
pub fn hmac_sm3_parts(key : Bytes, parts : Array[BytesView]) -> Bytes {
  let k = if key.length() > SM3_BLOCK_SIZE { sm3(key) } else { key }
  let ipad = FixedArray::make(SM3_BLOCK_SIZE, b'\x36')
  let opad = FixedArray::make(SM3_BLOCK_SIZE, b'\x5c')
  for i = 0; i < k.length(); i = i + 1 {
    ipad[i] = (k[i].to_uint() ^ 0x36U).to_byte()
    opad[i] = (k[i].to_uint() ^ 0x5CU).to_byte()
  }
  let inner = Sm3::new()
  inner.update(Bytes::from_array(ipad))
  for i = 0; i < parts.length(); i = i + 1 {
    inner.update_view(parts[i])
  }
  let inner_digest = inner.finalize()
  let outer = Sm3::new()
  outer.update(Bytes::from_array(opad))
  outer.update(inner_digest)
  outer.finalize()
}

///|
/// GM/T 0024-2023 §6.3 TLCP PRF using P_SM3:
/// `PRF(secret, label, seed) = P_SM3(secret, label + seed)`
pub fn tlcp_prf(
  secret : Bytes,
  label : Bytes,
  seed : Bytes,
  out_len : Int,
) -> Bytes {
  if out_len <= 0 {
    return b""
  }
  let label_seed = FixedArray::make(label.length() + seed.length(), b'\x00')
  for i = 0; i < label.length(); i = i + 1 {
    label_seed[i] = label[i]
  }
  for i = 0; i < seed.length(); i = i + 1 {
    label_seed[label.length() + i] = seed[i]
  }
  let full_seed = Bytes::from_array(label_seed)
  let out = FixedArray::make(out_len, b'\x00')
  let mut written = 0
  let mut a = hmac_sm3(secret, full_seed)
  while written < out_len {
    let block = hmac_sm3_parts(secret, [a[:], full_seed[:]])
    let take = if out_len - written < SM3_DIGEST_SIZE {
      out_len - written
    } else {
      SM3_DIGEST_SIZE
    }
    for i = 0; i < take; i = i + 1 {
      out[written + i] = block[i]
    }
    written = written + take
    if written < out_len {
      a = hmac_sm3(secret, a)
    }
  }
  Bytes::from_array(out)
}

///|
/// GB/T 32918.4 SM2 Key Derivation Function (KDF) using SM3.
pub fn kdf_sm3(z : Bytes, klen : Int) -> Bytes {
  if klen <= 0 {
    return b""
  }
  let out = FixedArray::make(klen, b'\x00')
  let ct_buf = FixedArray::make(4, b'\x00')
  let mut written = 0
  let mut ct : UInt = 1U
  while written < klen {
    write_be32_arr(ct_buf, 0, ct)
    let h = Sm3::new()
    h.update(z)
    h.update(Bytes::from_array(ct_buf))
    let digest = h.finalize()
    let take = if klen - written < SM3_DIGEST_SIZE {
      klen - written
    } else {
      SM3_DIGEST_SIZE
    }
    for i = 0; i < take; i = i + 1 {
      out[written + i] = digest[i]
    }
    written = written + take
    ct = ct + 1U
  }
  Bytes::from_array(out)
}
