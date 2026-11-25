///|
/// GB/T 32907-2016 SM4 Block Cipher with CBC, CTR, and RFC 8998 / GM/T 0024-2023 GCM AEAD.

///|
pub const SM4_KEY_SIZE : Int = 16

///|
pub const SM4_BLOCK_SIZE : Int = 16

///|
pub const SM4_GCM_TAG_SIZE : Int = 16

///|
let sbox : FixedArray[Byte] = [
  b'\xd6', b'\x90', b'\xe9', b'\xfe', b'\xcc', b'\xe1', b'\x3d', b'\xb7', b'\x16',
  b'\xb6', b'\x14', b'\xc2', b'\x28', b'\xfb', b'\x2c', b'\x05', b'\x2b', b'\x67',
  b'\x9a', b'\x76', b'\x2a', b'\xbe', b'\x04', b'\xc3', b'\xaa', b'\x44', b'\x13',
  b'\x26', b'\x49', b'\x86', b'\x06', b'\x99', b'\x9c', b'\x42', b'\x50', b'\xf4',
  b'\x91', b'\xef', b'\x98', b'\x7a', b'\x33', b'\x54', b'\x0b', b'\x43', b'\xed',
  b'\xcf', b'\xac', b'\x62', b'\xe4', b'\xb3', b'\x1c', b'\xa9', b'\xc9', b'\x08',
  b'\xe8', b'\x95', b'\x80', b'\xdf', b'\x94', b'\xfa', b'\x75', b'\x8f', b'\x3f',
  b'\xa6', b'\x47', b'\x07', b'\xa7', b'\xfc', b'\xf3', b'\x73', b'\x17', b'\xba',
  b'\x83', b'\x59', b'\x3c', b'\x19', b'\xe6', b'\x85', b'\x4f', b'\xa8', b'\x68',
  b'\x6b', b'\x81', b'\xb2', b'\x71', b'\x64', b'\xda', b'\x8b', b'\xf8', b'\xeb',
  b'\x0f', b'\x4b', b'\x70', b'\x56', b'\x9d', b'\x35', b'\x1e', b'\x24', b'\x0e',
  b'\x5e', b'\x63', b'\x58', b'\xd1', b'\xa2', b'\x25', b'\x22', b'\x7c', b'\x3b',
  b'\x01', b'\x21', b'\x78', b'\x87', b'\xd4', b'\x00', b'\x46', b'\x57', b'\x9f',
  b'\xd3', b'\x27', b'\x52', b'\x4c', b'\x36', b'\x02', b'\xe7', b'\xa0', b'\xc4',
  b'\xc8', b'\x9e', b'\xea', b'\xbf', b'\x8a', b'\xd2', b'\x40', b'\xc7', b'\x38',
  b'\xb5', b'\xa3', b'\xf7', b'\xf2', b'\xce', b'\xf9', b'\x61', b'\x15', b'\xa1',
  b'\xe0', b'\xae', b'\x5d', b'\xa4', b'\x9b', b'\x34', b'\x1a', b'\x55', b'\xad',
  b'\x93', b'\x32', b'\x30', b'\xf5', b'\x8c', b'\xb1', b'\xe3', b'\x1d', b'\xf6',
  b'\xe2', b'\x2e', b'\x82', b'\x66', b'\xca', b'\x60', b'\xc0', b'\x29', b'\x23',
  b'\xab', b'\x0d', b'\x53', b'\x4e', b'\x6f', b'\xd5', b'\xdb', b'\x37', b'\x45',
  b'\xde', b'\xfd', b'\x8e', b'\x2f', b'\x03', b'\xff', b'\x6a', b'\x72', b'\x6d',
  b'\x6c', b'\x5b', b'\x51', b'\x8d', b'\x1b', b'\xaf', b'\x92', b'\xbb', b'\xdd',
  b'\xbc', b'\x7f', b'\x11', b'\xd9', b'\x5c', b'\x41', b'\x1f', b'\x10', b'\x5a',
  b'\xd8', b'\x0a', b'\xc1', b'\x31', b'\x88', b'\xa5', b'\xcd', b'\x7b', b'\xbd',
  b'\x2d', b'\x74', b'\xd0', b'\x12', b'\xb8', b'\xe5', b'\xb4', b'\xb0', b'\x89',
  b'\x69', b'\x97', b'\x4a', b'\x0c', b'\x96', b'\x77', b'\x7e', b'\x65', b'\xb9',
  b'\xf1', b'\x09', b'\xc5', b'\x6e', b'\xc6', b'\x84', b'\x18', b'\xf0', b'\x7d',
  b'\xec', b'\x3a', b'\xdc', b'\x4d', b'\x20', b'\x79', b'\xee', b'\x5f', b'\x3e',
  b'\xd7', b'\xcb', b'\x39', b'\x48',
]

///|
let ck : FixedArray[UInt] = [
  0x00070E15U, 0x1C232A31U, 0x383F464DU, 0x545B6269U, 0x70777E85U, 0x8C939AA1U, 0xA8AFB6BDU,
  0xC4CBD2D9U, 0xE0E7EEF5U, 0xFC030A11U, 0x181F262DU, 0x343B4249U, 0x50575E65U, 0x6C737A81U,
  0x888F969DU, 0xA4ABB2B9U, 0xC0C7CED5U, 0xDCE3EAF1U, 0xF8FF060DU, 0x141B2229U, 0x30373E45U,
  0x4C535A61U, 0x686F767DU, 0x848B9299U, 0xA0A7AEB5U, 0xBCC3CAD1U, 0xD8DFE6EDU, 0xF4FB0209U,
  0x10171E25U, 0x2C333A41U, 0x484F565DU, 0x646B7279U,
]

///|
fn rotl32(x : UInt, n : Int) -> UInt {
  (x << n) | (x >> (32 - n))
}

///|
fn tau(a : UInt) -> UInt {
  let b0 = sbox[((a >> 24) & 0xFFU).reinterpret_as_int()].to_uint()
  let b1 = sbox[((a >> 16) & 0xFFU).reinterpret_as_int()].to_uint()
  let b2 = sbox[((a >> 8) & 0xFFU).reinterpret_as_int()].to_uint()
  let b3 = sbox[(a & 0xFFU).reinterpret_as_int()].to_uint()
  (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
}

///|
fn t_enc(x : UInt) -> UInt {
  let b = tau(x)
  b ^ rotl32(b, 2) ^ rotl32(b, 10) ^ rotl32(b, 18) ^ rotl32(b, 24)
}

///|
fn t_key(x : UInt) -> UInt {
  let b = tau(x)
  b ^ rotl32(b, 13) ^ rotl32(b, 23)
}

///|
fn read_be32_bytes(b : Bytes, off : Int) -> UInt {
  (b[off].to_uint() << 24) |
  (b[off + 1].to_uint() << 16) |
  (b[off + 2].to_uint() << 8) |
  b[off + 3].to_uint()
}

///|
fn read_be32_arr(b : FixedArray[Byte], off : Int) -> UInt {
  (b[off].to_uint() << 24) |
  (b[off + 1].to_uint() << 16) |
  (b[off + 2].to_uint() << 8) |
  b[off + 3].to_uint()
}

///|
fn write_be32_arr(b : FixedArray[Byte], off : Int, v : UInt) -> Unit {
  b[off] = ((v >> 24) & 0xFFU).to_byte()
  b[off + 1] = ((v >> 16) & 0xFFU).to_byte()
  b[off + 2] = ((v >> 8) & 0xFFU).to_byte()
  b[off + 3] = (v & 0xFFU).to_byte()
}

///|
#derive(Debug, Eq)
pub suberror Sm4Error {
  InvalidKeyLength(Int)
  InvalidIvLength(Int)
  InvalidBlockLength(Int)
  InvalidPadding
  AuthFailed
}

///|
/// Expanded SM4 round keys (32 rounds).
pub struct Sm4Key {
  rk : FixedArray[UInt]
}

///|
/// Expands a 16-byte SM4 key into 32 round keys.
pub fn Sm4Key::new(key : Bytes) -> Sm4Key raise Sm4Error {
  if key.length() != SM4_KEY_SIZE {
    raise InvalidKeyLength(key.length())
  }
  let mk0 = read_be32_bytes(key, 0)
  let mk1 = read_be32_bytes(key, 4)
  let mk2 = read_be32_bytes(key, 8)
  let mk3 = read_be32_bytes(key, 12)
  let mut k0 = mk0 ^ 0xA3B1BAC6U
  let mut k1 = mk1 ^ 0x56AA3350U
  let mut k2 = mk2 ^ 0x677D9197U
  let mut k3 = mk3 ^ 0xB27022DCU
  let rk = FixedArray::make(32, 0U)
  for i = 0; i < 32; i = i + 1 {
    let k4 = k0 ^ t_key(k1 ^ k2 ^ k3 ^ ck[i])
    rk[i] = k4
    k0 = k1
    k1 = k2
    k2 = k3
    k3 = k4
  }
  { rk, }
}

///|
/// Encrypts a single 16-byte block in place.
pub fn Sm4Key::encrypt_block_inplace(
  self : Sm4Key,
  buf : FixedArray[Byte],
  off : Int,
) -> Unit {
  let mut x0 = read_be32_arr(buf, off)
  let mut x1 = read_be32_arr(buf, off + 4)
  let mut x2 = read_be32_arr(buf, off + 8)
  let mut x3 = read_be32_arr(buf, off + 12)
  for i = 0; i < 32; i = i + 1 {
    let x4 = x0 ^ t_enc(x1 ^ x2 ^ x3 ^ self.rk[i])
    x0 = x1
    x1 = x2
    x2 = x3
    x3 = x4
  }
  write_be32_arr(buf, off, x3)
  write_be32_arr(buf, off + 4, x2)
  write_be32_arr(buf, off + 8, x1)
  write_be32_arr(buf, off + 12, x0)
}

///|
/// Decrypts a single 16-byte block in place.
pub fn Sm4Key::decrypt_block_inplace(
  self : Sm4Key,
  buf : FixedArray[Byte],
  off : Int,
) -> Unit {
  let mut x0 = read_be32_arr(buf, off)
  let mut x1 = read_be32_arr(buf, off + 4)
  let mut x2 = read_be32_arr(buf, off + 8)
  let mut x3 = read_be32_arr(buf, off + 12)
  for i = 0; i < 32; i = i + 1 {
    let x4 = x0 ^ t_enc(x1 ^ x2 ^ x3 ^ self.rk[31 - i])
    x0 = x1
    x1 = x2
    x2 = x3
    x3 = x4
  }
  write_be32_arr(buf, off, x3)
  write_be32_arr(buf, off + 4, x2)
  write_be32_arr(buf, off + 8, x1)
  write_be32_arr(buf, off + 12, x0)
}

///|
/// Encrypts a single 16-byte block.
pub fn Sm4Key::encrypt_block(
  self : Sm4Key,
  block : Bytes,
) -> Bytes raise Sm4Error {
  if block.length() != SM4_BLOCK_SIZE {
    raise InvalidBlockLength(block.length())
  }
  let buf = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    buf[i] = block[i]
  }
  self.encrypt_block_inplace(buf, 0)
  Bytes::from_array(buf)
}

///|
/// Decrypts a single 16-byte block.
pub fn Sm4Key::decrypt_block(
  self : Sm4Key,
  block : Bytes,
) -> Bytes raise Sm4Error {
  if block.length() != SM4_BLOCK_SIZE {
    raise InvalidBlockLength(block.length())
  }
  let buf = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    buf[i] = block[i]
  }
  self.decrypt_block_inplace(buf, 0)
  Bytes::from_array(buf)
}

///|
/// Raw SM4-CBC encryption (no padding added; `data.length()` must be a multiple of 16).
pub fn Sm4Key::cbc_encrypt_raw(
  self : Sm4Key,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise Sm4Error {
  if iv.length() != SM4_BLOCK_SIZE {
    raise InvalidIvLength(iv.length())
  }
  if data.length() % SM4_BLOCK_SIZE != 0 {
    raise InvalidBlockLength(data.length())
  }
  let out = FixedArray::make(data.length(), b'\x00')
  let prev = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    prev[i] = iv[i]
  }
  let mut off = 0
  while off < data.length() {
    for i = 0; i < 16; i = i + 1 {
      out[off + i] = (data[off + i].to_uint() ^ prev[i].to_uint()).to_byte()
    }
    self.encrypt_block_inplace(out, off)
    for i = 0; i < 16; i = i + 1 {
      prev[i] = out[off + i]
    }
    off = off + 16
  }
  Bytes::from_array(out)
}

///|
/// Raw SM4-CBC decryption (no padding stripped; `data.length()` must be a multiple of 16).
pub fn Sm4Key::cbc_decrypt_raw(
  self : Sm4Key,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise Sm4Error {
  if iv.length() != SM4_BLOCK_SIZE {
    raise InvalidIvLength(iv.length())
  }
  if data.length() % SM4_BLOCK_SIZE != 0 {
    raise InvalidBlockLength(data.length())
  }
  let out = FixedArray::make(data.length(), b'\x00')
  let prev = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    prev[i] = iv[i]
  }
  let cur = FixedArray::make(16, b'\x00')
  let mut off = 0
  while off < data.length() {
    for i = 0; i < 16; i = i + 1 {
      cur[i] = data[off + i]
      out[off + i] = cur[i]
    }
    self.decrypt_block_inplace(out, off)
    for i = 0; i < 16; i = i + 1 {
      out[off + i] = (out[off + i].to_uint() ^ prev[i].to_uint()).to_byte()
      prev[i] = cur[i]
    }
    off = off + 16
  }
  Bytes::from_array(out)
}

///|
/// SM4-CBC encryption with PKCS#7 padding.
pub fn Sm4Key::cbc_encrypt_pkcs7(
  self : Sm4Key,
  iv : Bytes,
  plaintext : Bytes,
) -> Bytes raise Sm4Error {
  let pad_len = SM4_BLOCK_SIZE - plaintext.length() % SM4_BLOCK_SIZE
  let padded = FixedArray::make(plaintext.length() + pad_len, pad_len.to_byte())
  for i = 0; i < plaintext.length(); i = i + 1 {
    padded[i] = plaintext[i]
  }
  self.cbc_encrypt_raw(iv, Bytes::from_array(padded))
}

///|
/// SM4-CBC decryption with constant-time PKCS#7 padding verification.
pub fn Sm4Key::cbc_decrypt_pkcs7(
  self : Sm4Key,
  iv : Bytes,
  ciphertext : Bytes,
) -> Bytes raise Sm4Error {
  if ciphertext.length() == 0 || ciphertext.length() % SM4_BLOCK_SIZE != 0 {
    raise InvalidBlockLength(ciphertext.length())
  }
  let dec = self.cbc_decrypt_raw(iv, ciphertext)
  let n = dec.length()
  let pad_len = dec[n - 1].to_uint()
  // Valid PKCS#7 pad_len must satisfy 1 <= pad_len <= 16
  let mut good = @ct.ct_lt_u32(0U, pad_len) & @ct.ct_lt_u32(pad_len, 17U)
  // Always inspect all last 16 bytes in constant time
  for i = 0; i < 16; i = i + 1 {
    let in_pad = @ct.ct_lt_u32(i.reinterpret_as_uint(), pad_len)
    let b = dec[n - 1 - i].to_uint()
    let byte_ok = @ct.ct_eq_u32(b, pad_len)
    // If in_pad == 1, require byte_ok == 1
    good = good & (@ct.ct_select_u32(in_pad, byte_ok, 1U))
  }
  if good == 0U {
    raise InvalidPadding
  }
  let out_len = n - pad_len.reinterpret_as_int()
  let out = FixedArray::make(out_len, b'\x00')
  for i = 0; i < out_len; i = i + 1 {
    out[i] = dec[i]
  }
  Bytes::from_array(out)
}

///|
/// SM4-CTR encryption/decryption (big-endian 128-bit counter increment).
pub fn Sm4Key::ctr_crypt(
  self : Sm4Key,
  iv : Bytes,
  data : Bytes,
) -> Bytes raise Sm4Error {
  if iv.length() != SM4_BLOCK_SIZE {
    raise InvalidIvLength(iv.length())
  }
  let ctr = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    ctr[i] = iv[i]
  }
  let ks = FixedArray::make(16, b'\x00')
  let out = FixedArray::make(data.length(), b'\x00')
  let mut off = 0
  while off < data.length() {
    for i = 0; i < 16; i = i + 1 {
      ks[i] = ctr[i]
    }
    self.encrypt_block_inplace(ks, 0)
    let take = if data.length() - off < 16 { data.length() - off } else { 16 }
    for i = 0; i < take; i = i + 1 {
      out[off + i] = (data[off + i].to_uint() ^ ks[i].to_uint()).to_byte()
    }
    // Increment 128-bit counter big-endian
    let mut carry = 1U
    for i = 15; i >= 0; i = i - 1 {
      let sum = ctr[i].to_uint() + carry
      ctr[i] = (sum & 0xFFU).to_byte()
      carry = sum >> 8
    }
    off = off + take
  }
  Bytes::from_array(out)
}

///|
/// GF(2^128) multiplication for GCM GHASH: X * Y mod (x^128 + x^7 + x^2 + x + 1).
/// Uses NIST SP 800-38D bit reflection convention (bit 0 is MSB of byte 0).
fn ghash_mul(x_hi : UInt64, x_lo : UInt64, y_hi : UInt64, y_lo : UInt64) -> (UInt64, UInt64) {
  let mut z_hi : UInt64 = 0UL
  let mut z_lo : UInt64 = 0UL
  let mut v_hi = y_hi
  let mut v_lo = y_lo
  for i = 0; i < 128; i = i + 1 {
    let bit = if i < 64 {
      (x_hi >> (63 - i)) & 1UL
    } else {
      (x_lo >> (127 - i)) & 1UL
    }
    let mask = 0UL - bit
    z_hi = z_hi ^ (v_hi & mask)
    z_lo = z_lo ^ (v_lo & mask)
    let lsb = v_lo & 1UL
    let r_mask = 0UL - lsb
    let new_lo = (v_lo >> 1) | (v_hi << 63)
    let new_hi = (v_hi >> 1) ^ (0xE100000000000000UL & r_mask)
    v_hi = new_hi
    v_lo = new_lo
  }
  (z_hi, z_lo)
}

///|
fn read_be64_arr(b : FixedArray[Byte], off : Int) -> UInt64 {
  (b[off].to_uint64() << 56) |
  (b[off + 1].to_uint64() << 48) |
  (b[off + 2].to_uint64() << 40) |
  (b[off + 3].to_uint64() << 32) |
  (b[off + 4].to_uint64() << 24) |
  (b[off + 5].to_uint64() << 16) |
  (b[off + 6].to_uint64() << 8) |
  b[off + 7].to_uint64()
}

///|
fn write_be64_arr(b : FixedArray[Byte], off : Int, v : UInt64) -> Unit {
  b[off] = ((v >> 56) & 0xFFUL).to_byte()
  b[off + 1] = ((v >> 48) & 0xFFUL).to_byte()
  b[off + 2] = ((v >> 40) & 0xFFUL).to_byte()
  b[off + 3] = ((v >> 32) & 0xFFUL).to_byte()
  b[off + 4] = ((v >> 24) & 0xFFUL).to_byte()
  b[off + 5] = ((v >> 16) & 0xFFUL).to_byte()
  b[off + 6] = ((v >> 8) & 0xFFUL).to_byte()
  b[off + 7] = (v & 0xFFUL).to_byte()
}

///|
fn ghash_update_bytes(
  h_hi : UInt64,
  h_lo : UInt64,
  acc_hi : UInt64,
  acc_lo : UInt64,
  data : Bytes,
) -> (UInt64, UInt64) {
  let mut y_hi = acc_hi
  let mut y_lo = acc_lo
  let blk = FixedArray::make(16, b'\x00')
  let mut off = 0
  while off < data.length() {
    let take = if data.length() - off < 16 { data.length() - off } else { 16 }
    for i = 0; i < 16; i = i + 1 {
      blk[i] = if i < take { data[off + i] } else { b'\x00' }
    }
    let b_hi = read_be64_arr(blk, 0)
    let b_lo = read_be64_arr(blk, 8)
    let (nh, nl) = ghash_mul(y_hi ^ b_hi, y_lo ^ b_lo, h_hi, h_lo)
    y_hi = nh
    y_lo = nl
    off = off + take
  }
  (y_hi, y_lo)
}

///|
fn inc32(counter : FixedArray[Byte]) -> Unit {
  let c = read_be32_arr(counter, 12) + 1U
  write_be32_arr(counter, 12, c)
}

///|
fn Sm4Key::gcm_j0(
  self : Sm4Key,
  h_hi : UInt64,
  h_lo : UInt64,
  iv : Bytes,
) -> FixedArray[Byte] raise Sm4Error {
  if iv.length() == 0 {
    raise InvalidIvLength(0)
  }
  let j0 = FixedArray::make(16, b'\x00')
  if iv.length() == 12 {
    for i = 0; i < 12; i = i + 1 {
      j0[i] = iv[i]
    }
    j0[15] = b'\x01'
  } else {
    let (yh, yl) = ghash_update_bytes(h_hi, h_lo, 0UL, 0UL, iv)
    let len_hi = 0UL
    let len_lo = iv.length().to_uint64() << 3
    let (fh, fl) = ghash_mul(yh ^ len_hi, yl ^ len_lo, h_hi, h_lo)
    write_be64_arr(j0, 0, fh)
    write_be64_arr(j0, 8, fl)
  }
  ignore(self)
  j0
}

///|
fn Sm4Key::gctr(
  self : Sm4Key,
  icb : FixedArray[Byte],
  data : Bytes,
) -> Bytes {
  let ctr = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    ctr[i] = icb[i]
  }
  let ks = FixedArray::make(16, b'\x00')
  let out = FixedArray::make(data.length(), b'\x00')
  let mut off = 0
  while off < data.length() {
    for i = 0; i < 16; i = i + 1 {
      ks[i] = ctr[i]
    }
    self.encrypt_block_inplace(ks, 0)
    let take = if data.length() - off < 16 { data.length() - off } else { 16 }
    for i = 0; i < take; i = i + 1 {
      out[off + i] = (data[off + i].to_uint() ^ ks[i].to_uint()).to_byte()
    }
    inc32(ctr)
    off = off + take
  }
  Bytes::from_array(out)
}

///|
/// RFC 8998 / GM/T 0024-2023 SM4-GCM authenticated encryption.
/// Returns `(ciphertext, tag)` where `tag.length() == 16`.
pub fn Sm4Key::gcm_encrypt(
  self : Sm4Key,
  iv : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> (Bytes, Bytes) raise Sm4Error {
  let h_buf = FixedArray::make(16, b'\x00')
  self.encrypt_block_inplace(h_buf, 0)
  let h_hi = read_be64_arr(h_buf, 0)
  let h_lo = read_be64_arr(h_buf, 8)
  let j0 = self.gcm_j0(h_hi, h_lo, iv)
  let cb = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    cb[i] = j0[i]
  }
  inc32(cb)
  let ciphertext = self.gctr(cb, plaintext)
  let (y1h, y1l) = ghash_update_bytes(h_hi, h_lo, 0UL, 0UL, aad)
  let (y2h, y2l) = ghash_update_bytes(h_hi, h_lo, y1h, y1l, ciphertext)
  let len_hi = aad.length().to_uint64() << 3
  let len_lo = ciphertext.length().to_uint64() << 3
  let (sh, sl) = ghash_mul(y2h ^ len_hi, y2l ^ len_lo, h_hi, h_lo)
  let s_bytes = FixedArray::make(16, b'\x00')
  write_be64_arr(s_bytes, 0, sh)
  write_be64_arr(s_bytes, 8, sl)
  let tag = self.gctr(j0, Bytes::from_array(s_bytes))
  (ciphertext, tag)
}

///|
/// RFC 8998 / GM/T 0024-2023 SM4-GCM authenticated decryption.
/// Verifies the 16-byte tag in constant time before releasing plaintext.
pub fn Sm4Key::gcm_decrypt(
  self : Sm4Key,
  iv : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
) -> Bytes raise Sm4Error {
  if tag.length() != SM4_GCM_TAG_SIZE {
    raise AuthFailed
  }
  let h_buf = FixedArray::make(16, b'\x00')
  self.encrypt_block_inplace(h_buf, 0)
  let h_hi = read_be64_arr(h_buf, 0)
  let h_lo = read_be64_arr(h_buf, 8)
  let j0 = self.gcm_j0(h_hi, h_lo, iv)
  let (y1h, y1l) = ghash_update_bytes(h_hi, h_lo, 0UL, 0UL, aad)
  let (y2h, y2l) = ghash_update_bytes(h_hi, h_lo, y1h, y1l, ciphertext)
  let len_hi = aad.length().to_uint64() << 3
  let len_lo = ciphertext.length().to_uint64() << 3
  let (sh, sl) = ghash_mul(y2h ^ len_hi, y2l ^ len_lo, h_hi, h_lo)
  let s_bytes = FixedArray::make(16, b'\x00')
  write_be64_arr(s_bytes, 0, sh)
  write_be64_arr(s_bytes, 8, sl)
  let expected_tag = self.gctr(j0, Bytes::from_array(s_bytes))
  if !@ct.ct_eq(expected_tag, tag) {
    raise AuthFailed
  }
  let cb = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    cb[i] = j0[i]
  }
  inc32(cb)
  self.gctr(cb, ciphertext)
}
