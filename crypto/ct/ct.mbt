///|
/// Constant-time primitives to mitigate timing side-channel attacks
/// (e.g., Lucky13 / CBC padding oracle and AEAD tag verification).

///|
/// Constant-time equality comparison over two `Bytes` values.
/// Returns `false` immediately if lengths differ, otherwise compares
/// every byte without short-circuiting.
pub fn ct_eq(a : Bytes, b : Bytes) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff : UInt32 = 0U
  for i = 0; i < a.length(); i = i + 1 {
    diff = diff | (a[i].to_uint() ^ b[i].to_uint())
  }
  diff == 0U
}

///|
/// Constant-time equality comparison over two `BytesView` slices.
pub fn ct_eq_view(a : BytesView, b : BytesView) -> Bool {
  if a.length() != b.length() {
    return false
  }
  let mut diff : UInt32 = 0U
  for i = 0; i < a.length(); i = i + 1 {
    diff = diff | (a[i].to_uint() ^ b[i].to_uint())
  }
  diff == 0U
}

///|
/// Constant-time check whether a `UInt` equals zero.
/// Returns `1U` if `x == 0U`, else `0U`.
pub fn ct_is_zero_u32(x : UInt32) -> UInt32 {
  // If x == 0: (~x & (x - 1)) has MSB = 1
  let neg = 0U - x
  let nz = (x | neg) >> 31
  1U - nz
}

///|
/// Constant-time equality for two `UInt` values.
/// Returns `1U` if `a == b`, else `0U`.
pub fn ct_eq_u32(a : UInt32, b : UInt32) -> UInt32 {
  ct_is_zero_u32(a ^ b)
}

///|
/// Constant-time unsigned less-than (`a < b`) for 32-bit unsigned ints.
/// Returns `1U` if `a < b`, else `0U`.
pub fn ct_lt_u32(a : UInt32, b : UInt32) -> UInt32 {
  let a64 = a.to_uint64()
  let b64 = b.to_uint64()
  ((a64 - b64) >> 63).to_uint()
}

///|
/// Constant-time selection: returns `a` if `cond == 1U`, `b` if `cond == 0U`.
pub fn ct_select_u32(cond : UInt32, a : UInt32, b : UInt32) -> UInt32 {
  let mask = 0U - (cond & 1U)
  (a & mask) | (b & mask.lnot())
}

///|
/// Constant-time byte selection: returns `a` if `cond == 1U`, `b` if `cond == 0U`.
pub fn ct_select_byte(cond : UInt32, a : Byte, b : Byte) -> Byte {
  ct_select_u32(cond, a.to_uint(), b.to_uint()).to_byte()
}

///|
/// Overwrites a mutable byte buffer with zeros.
pub fn zeroize(buf : FixedArray[Byte]) -> Unit {
  for i = 0; i < buf.length(); i = i + 1 {
    buf[i] = b'\x00'
  }
}
