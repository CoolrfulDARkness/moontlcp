///|
/// 256-bit finite field arithmetic over SM2 prime field F_p and scalar field F_n.
/// Uses 8 x 32-bit little-endian limbs with UInt64 intermediate products,
/// Solinas fast reduction modulo p, and CIOS Montgomery multiplication modulo n.

///|
/// SM2 prime p = 2^256 - 2^224 - 2^96 + 2^64 - 1
/// = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_FFFFFFFF_00000000_FFFFFFFF_FFFFFFFF
let sm2_p : FixedArray[UInt32] = [
  0xFFFFFFFFU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
  0xFFFFFFFEU,
]

///|
/// SM2 curve order n
/// = 0xFFFFFFFE_FFFFFFFF_FFFFFFFF_FFFFFFFF_7203DF6B_21C6052B_53BBF409_39D54123
let sm2_n : FixedArray[UInt32] = [
  0x39D54123U, 0x53BBF409U, 0x21C6052BU, 0x7203DF6BU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
  0xFFFFFFFEU,
]

///|
/// SM2 n - 1 (maximum valid scalar for signature r, s, k; private key requires <= n - 2)
let sm2_n_minus_1 : FixedArray[UInt32] = [
  0x39D54122U, 0x53BBF409U, 0x21C6052BU, 0x7203DF6BU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
  0xFFFFFFFEU,
]

///|
/// SM2 n - 2 (used for private key upper bound and Fermat inversion mod n)
let sm2_n_minus_2 : FixedArray[UInt32] = [
  0x39D54121U, 0x53BBF409U, 0x21C6052BU, 0x7203DF6BU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
  0xFFFFFFFEU,
]

///|
/// Montgomery constant -n^{-1} mod 2^32 for scalar field F_n
let mont_n0_prime : UInt32 = 0x72350975U

///|
/// Montgomery constant R mod n = 2^256 mod n
let mont_r1_n : FixedArray[UInt32] = [
  0xC62ABEDDU, 0xAC440BF6U, 0xDE39FAD4U, 0x8DFC2094U, 0x00000000U, 0x00000000U, 0x00000000U,
  0x00000001U,
]

///|
/// Montgomery constant R^2 mod n = 2^512 mod n
let mont_r2_n : FixedArray[UInt32] = [
  0x7C114F20U, 0x901192AFU, 0xDE6FA2FAU, 0x3464504AU, 0x3AFFE0D4U, 0x620FC84CU, 0xA22B3D3BU,
  0x1EB5E412U,
]

///|
/// 256-bit unsigned integer represented as 8 x 32-bit little-endian limbs.
#derive(Debug)
priv struct U256 {
  limbs : FixedArray[UInt32]
}

///|
fn u256_zero() -> U256 {
  { limbs: FixedArray::make(8, 0U), }
}

///|
fn u256_one() -> U256 {
  { limbs: [1U, 0U, 0U, 0U, 0U, 0U, 0U, 0U], }
}

///|
fn u256_clone(a : U256) -> U256 {
  let out = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    out[i] = a.limbs[i]
  }
  { limbs: out, }
}

///|
fn u256_from_limbs(arr : FixedArray[UInt32]) -> U256 {
  let out = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    out[i] = arr[i]
  }
  { limbs: out, }
}

///|
fn u256_is_zero(a : U256) -> Bool {
  let mut acc = 0U
  for i = 0; i < 8; i = i + 1 {
    acc = acc | a.limbs[i]
  }
  acc == 0U
}

///|
fn u256_eq(a : U256, b : U256) -> Bool {
  let mut diff = 0U
  for i = 0; i < 8; i = i + 1 {
    diff = diff | (a.limbs[i] ^ b.limbs[i])
  }
  diff == 0U
}

///|
/// Constant-time select between two U256 values: returns `a` if `cond == 1U`, `b` if `cond == 0U`.
fn u256_ct_select(cond : UInt32, a : U256, b : U256) -> U256 {
  let out = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    out[i] = @ct.ct_select_u32(cond, a.limbs[i], b.limbs[i])
  }
  { limbs: out, }
}

///|
/// Unsigned comparison of two 256-bit integers: returns -1 if a < b, 0 if a == b, 1 if a > b.
fn u256_cmp_arr(a : FixedArray[UInt32], b : FixedArray[UInt32]) -> Int32 {
  for i = 7; i >= 0; i = i - 1 {
    if a[i] < b[i] {
      return -1
    }
    if a[i] > b[i] {
      return 1
    }
  }
  0
}

///|
/// Parses a 32-byte big-endian `BytesView` into a `U256`.
fn u256_from_be_view(data : BytesView) -> U256 {
  let limbs = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    let off = (7 - i) * 4
    limbs[i] = (data[off].to_uint() << 24) |
      (data[off + 1].to_uint() << 16) |
      (data[off + 2].to_uint() << 8) |
      data[off + 3].to_uint()
  }
  { limbs, }
}

///|
/// Serializes a `U256` to 32-byte big-endian `Bytes`.
fn u256_to_be_bytes(a : U256) -> Bytes {
  let out = FixedArray::make(32, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    let off = (7 - i) * 4
    let v = a.limbs[i]
    out[off] = ((v >> 24) & 0xFFU).to_byte()
    out[off + 1] = ((v >> 16) & 0xFFU).to_byte()
    out[off + 2] = ((v >> 8) & 0xFFU).to_byte()
    out[off + 3] = (v & 0xFFU).to_byte()
  }
  Bytes::from_array(out)
}

///|
/// Returns the 4-bit nibble at index `nib` (0 = least significant nibble, 63 = most significant).
fn u256_get_nibble(a : U256, nib : Int32) -> UInt32 {
  let limb_idx = nib >> 3
  let shift = (nib & 7) << 2
  (a.limbs[limb_idx] >> shift) & 0xFU
}

///|
/// Returns bit `bit_idx` (0..255) of `a` as 0U or 1U.
fn u256_get_bit(a : U256, bit_idx : Int32) -> UInt32 {
  let limb_idx = bit_idx >> 5
  let shift = bit_idx & 31
  (a.limbs[limb_idx] >> shift) & 1U
}

///|
/// Adds two 8-limb arrays into a new array and returns `(result, carry_out)`.
fn raw_add(
  a : FixedArray[UInt32],
  b : FixedArray[UInt32],
) -> (FixedArray[UInt32], UInt32) {
  let out = FixedArray::make(8, 0U)
  let mut carry = 0UL
  for i = 0; i < 8; i = i + 1 {
    let s = a[i].to_uint64() + b[i].to_uint64() + carry
    out[i] = (s & 0xFFFFFFFFUL).to_uint()
    carry = s >> 32
  }
  (out, carry.to_uint())
}

///|
/// Subtracts `b` from `a` (8 limbs) and returns `(result, borrow_out)` where borrow is 0U or 1U.
fn raw_sub(
  a : FixedArray[UInt32],
  b : FixedArray[UInt32],
) -> (FixedArray[UInt32], UInt32) {
  let out = FixedArray::make(8, 0U)
  let mut borrow = 0UL
  for i = 0; i < 8; i = i + 1 {
    let ai = a[i].to_uint64()
    let bi = b[i].to_uint64() + borrow
    if ai >= bi {
      out[i] = (ai - bi).to_uint()
      borrow = 0UL
    } else {
      out[i] = ((1UL << 32) + ai - bi).to_uint()
      borrow = 1UL
    }
  }
  (out, borrow.to_uint())
}

///|
/// Full 256 x 256 -> 512-bit unsigned multiplication producing 16 little-endian 32-bit limbs.
fn raw_mul512(
  a : FixedArray[UInt32],
  b : FixedArray[UInt32],
) -> FixedArray[UInt32] {
  let prod = FixedArray::make(16, 0U)
  for i = 0; i < 8; i = i + 1 {
    let ai = a[i].to_uint64()
    let mut carry = 0UL
    for j = 0; j < 8; j = j + 1 {
      let s = prod[i + j].to_uint64() + ai * b[j].to_uint64() + carry
      prod[i + j] = (s & 0xFFFFFFFFUL).to_uint()
      carry = s >> 32
    }
    prod[i + 8] = carry.to_uint()
  }
  prod
}

// ============================================================================
// Prime Field F_p Operations (mod sm2_p)
// ============================================================================

///|
fn fe_is_canonical(a : U256) -> Bool {
  u256_cmp_arr(a.limbs, sm2_p) < 0
}

///|
fn fe_add(a : U256, b : U256) -> U256 {
  let (sum, carry) = raw_add(a.limbs, b.limbs)
  let (sub, borrow) = raw_sub(sum, sm2_p)
  let use_sub = if carry != 0U || borrow == 0U { 1U } else { 0U }
  u256_ct_select(use_sub, { limbs: sub, }, { limbs: sum, })
}

///|
fn fe_sub(a : U256, b : U256) -> U256 {
  let (diff, borrow) = raw_sub(a.limbs, b.limbs)
  let (added, _) = raw_add(diff, sm2_p)
  u256_ct_select(borrow, { limbs: added, }, { limbs: diff, })
}

///|
fn fe_neg(a : U256) -> U256 {
  if u256_is_zero(a) {
    u256_zero()
  } else {
    let (diff, _) = raw_sub(sm2_p, a.limbs)
    { limbs: diff, }
  }
}

///|
fn fe_double(a : U256) -> U256 {
  fe_add(a, a)
}

///|
/// Fast Solinas reduction of a 512-bit product (16 x 32-bit limbs) modulo SM2 prime p.
/// Uses 2^256 === 2^224 + 2^96 - 2^64 + 1 (mod p).
fn fe_reduce512(c : FixedArray[UInt32]) -> U256 {
  let c0 = c[0].to_uint64().reinterpret_as_int64()
  let c1 = c[1].to_uint64().reinterpret_as_int64()
  let c2 = c[2].to_uint64().reinterpret_as_int64()
  let c3 = c[3].to_uint64().reinterpret_as_int64()
  let c4 = c[4].to_uint64().reinterpret_as_int64()
  let c5 = c[5].to_uint64().reinterpret_as_int64()
  let c6 = c[6].to_uint64().reinterpret_as_int64()
  let c7 = c[7].to_uint64().reinterpret_as_int64()
  let c8 = c[8].to_uint64().reinterpret_as_int64()
  let c9 = c[9].to_uint64().reinterpret_as_int64()
  let c10 = c[10].to_uint64().reinterpret_as_int64()
  let c11 = c[11].to_uint64().reinterpret_as_int64()
  let c12 = c[12].to_uint64().reinterpret_as_int64()
  let c13 = c[13].to_uint64().reinterpret_as_int64()
  let c14 = c[14].to_uint64().reinterpret_as_int64()
  let c15 = c[15].to_uint64().reinterpret_as_int64()

  let s13_14_15 = c13 + c14 + c15
  let mut acc = c0 + c8 + c9 + c10 + c11 + c12 + (s13_14_15 << 1)
  let r0 = acc & 0xFFFFFFFFL
  acc = (acc >> 32) + c1 + c9 + c10 + c11 + c12 + c13 + ((c14 + c15) << 1)
  let r1 = acc & 0xFFFFFFFFL
  acc = (acc >> 32) + c2 - c8 - c9 - c13 - c14
  let r2 = acc & 0xFFFFFFFFL
  acc = (acc >> 32) + c3 + c8 + c11 + c12 + (c13 << 1) + c14 + c15
  let r3 = acc & 0xFFFFFFFFL
  acc = (acc >> 32) + c4 + c9 + c12 + c13 + (c14 << 1) + c15
  let r4 = acc & 0xFFFFFFFFL
  acc = (acc >> 32) + c5 + c10 + c13 + c14 + (c15 << 1)
  let r5 = acc & 0xFFFFFFFFL
  acc = (acc >> 32) + c6 + c11 + c14 + c15
  let r6 = acc & 0xFFFFFFFFL
  acc = (acc >> 32) +
    c7 +
    c8 +
    c9 +
    c10 +
    c11 +
    ((c12 + c13 + c14) << 1) +
    c15 * 3L
  let r7 = acc & 0xFFFFFFFFL
  let top = acc >> 32

  // Fold top * 2^256 === top * (2^224 + 2^96 - 2^64 + 1) (mod p)
  let limbs = FixedArray::make(8, 0U)
  let mut a2 = r0 + top
  limbs[0] = (a2 & 0xFFFFFFFFL).reinterpret_as_uint64().to_uint()
  a2 = (a2 >> 32) + r1
  limbs[1] = (a2 & 0xFFFFFFFFL).reinterpret_as_uint64().to_uint()
  a2 = (a2 >> 32) + r2 - top
  limbs[2] = (a2 & 0xFFFFFFFFL).reinterpret_as_uint64().to_uint()
  a2 = (a2 >> 32) + r3 + top
  limbs[3] = (a2 & 0xFFFFFFFFL).reinterpret_as_uint64().to_uint()
  a2 = (a2 >> 32) + r4
  limbs[4] = (a2 & 0xFFFFFFFFL).reinterpret_as_uint64().to_uint()
  a2 = (a2 >> 32) + r5
  limbs[5] = (a2 & 0xFFFFFFFFL).reinterpret_as_uint64().to_uint()
  a2 = (a2 >> 32) + r6
  limbs[6] = (a2 & 0xFFFFFFFFL).reinterpret_as_uint64().to_uint()
  a2 = (a2 >> 32) + r7 + top
  limbs[7] = (a2 & 0xFFFFFFFFL).reinterpret_as_uint64().to_uint()
  let mut carry = a2 >> 32

  let mut cur = limbs
  while carry < 0L {
    let (added, c_out) = raw_add(cur, sm2_p)
    cur = added
    carry = carry + c_out.to_uint64().reinterpret_as_int64()
  }
  while carry > 0L || u256_cmp_arr(cur, sm2_p) >= 0 {
    let (subbed, b_out) = raw_sub(cur, sm2_p)
    cur = subbed
    carry = carry - b_out.to_uint64().reinterpret_as_int64()
  }
  { limbs: cur, }
}

///|
fn fe_mul(a : U256, b : U256) -> U256 {
  fe_reduce512(raw_mul512(a.limbs, b.limbs))
}

///|
fn fe_sqr(a : U256) -> U256 {
  fe_mul(a, a)
}

///|
fn fe_sqr_n(a : U256, n : Int32) -> U256 {
  let mut cur = a
  for i = 0; i < n; i = i + 1 {
    cur = fe_sqr(cur)
  }
  cur
}

///|
/// Constant-time modular inverse in F_p via addition chain for a^(p - 2) mod p.
/// Returns 0 if a == 0.
fn fe_inv(a : U256) -> U256 {
  let x2 = fe_mul(fe_sqr(a), a) // 2 ones
  let x3 = fe_mul(fe_sqr(x2), a) // 3 ones
  let x4 = fe_mul(fe_sqr_n(x2, 2), x2) // 4 ones
  let x8 = fe_mul(fe_sqr_n(x4, 4), x4) // 8 ones
  let x12 = fe_mul(fe_sqr_n(x8, 4), x4) // 12 ones
  let x15 = fe_mul(fe_sqr_n(x12, 3), x3) // 15 ones
  let x16 = fe_mul(fe_sqr(x15), a) // 16 ones
  let x31 = fe_mul(fe_sqr_n(x16, 15), x15) // 31 ones
  let x32 = fe_mul(fe_sqr(x31), a) // 32 ones
  let x62 = fe_mul(fe_sqr_n(x31, 31), x31) // 62 ones
  let x64 = fe_mul(fe_sqr_n(x32, 32), x32) // 64 ones
  let x128 = fe_mul(fe_sqr_n(x64, 64), x64) // 128 ones

  // p - 2 = 31 ones | 0 | 128 ones | 32 zeros | 62 ones | 0 | 1
  let mut t = fe_sqr(x31)
  t = fe_mul(fe_sqr_n(t, 128), x128)
  t = fe_sqr_n(t, 32)
  t = fe_mul(fe_sqr_n(t, 62), x62)
  t = fe_mul(fe_sqr_n(t, 2), a)
  t
}

///|
/// Square root in F_p (since p === 3 mod 4): computes a^((p + 1) / 4) mod p.
/// Caller must verify `fe_sqr(root) == a`.
fn fe_sqrt(a : U256) -> U256 {
  let x2 = fe_mul(fe_sqr(a), a) // 2 ones
  let x3 = fe_mul(fe_sqr(x2), a) // 3 ones
  let x4 = fe_mul(fe_sqr_n(x2, 2), x2) // 4 ones
  let x8 = fe_mul(fe_sqr_n(x4, 4), x4) // 8 ones
  let x12 = fe_mul(fe_sqr_n(x8, 4), x4) // 12 ones
  let x15 = fe_mul(fe_sqr_n(x12, 3), x3) // 15 ones
  let x16 = fe_mul(fe_sqr(x15), a) // 16 ones
  let x31 = fe_mul(fe_sqr_n(x16, 15), x15) // 31 ones
  let x32 = fe_mul(fe_sqr(x31), a) // 32 ones
  let x64 = fe_mul(fe_sqr_n(x32, 32), x32) // 64 ones
  let x128 = fe_mul(fe_sqr_n(x64, 64), x64) // 128 ones

  // (p + 1) / 4 = 31 ones | 0 | 128 ones | 31 zeros | 1 | 62 zeros
  let mut t = fe_sqr(x31)
  t = fe_mul(fe_sqr_n(t, 128), x128)
  t = fe_mul(fe_sqr_n(t, 32), a)
  t = fe_sqr_n(t, 62)
  t
}

// ============================================================================
// Scalar Field F_n Operations (mod sm2_n)
// ============================================================================

///|
/// Reduces an arbitrary 256-bit unsigned integer modulo n (since 2^256 < 2*n, at most one subtraction).
fn sn_reduce_u256(a : U256) -> U256 {
  let (sub, borrow) = raw_sub(a.limbs, sm2_n)
  u256_ct_select(1U - borrow, { limbs: sub, }, a)
}

///|
fn sn_add(a : U256, b : U256) -> U256 {
  let (sum, carry) = raw_add(a.limbs, b.limbs)
  let (sub, borrow) = raw_sub(sum, sm2_n)
  let use_sub = if carry != 0U || borrow == 0U { 1U } else { 0U }
  u256_ct_select(use_sub, { limbs: sub, }, { limbs: sum, })
}

///|
fn sn_sub(a : U256, b : U256) -> U256 {
  let (diff, borrow) = raw_sub(a.limbs, b.limbs)
  let (added, _) = raw_add(diff, sm2_n)
  u256_ct_select(borrow, { limbs: added, }, { limbs: diff, })
}

///|
/// CIOS Montgomery multiplication modulo n: computes a * b * R^{-1} mod n.
fn sn_mont_mul(a : U256, b : U256) -> U256 {
  let t = FixedArray::make(10, 0UL)
  let n0p = mont_n0_prime.to_uint64()
  for i = 0; i < 8; i = i + 1 {
    let ai = a.limbs[i].to_uint64()
    let mut carry = 0UL
    for j = 0; j < 8; j = j + 1 {
      let s = t[j] + ai * b.limbs[j].to_uint64() + carry
      t[j] = s & 0xFFFFFFFFUL
      carry = s >> 32
    }
    let s8 = t[8] + carry
    t[8] = s8 & 0xFFFFFFFFUL
    t[9] = s8 >> 32

    let m = (t[0] * n0p) & 0xFFFFFFFFUL
    let mut c2 = (t[0] + m * sm2_n[0].to_uint64()) >> 32
    for j = 1; j < 8; j = j + 1 {
      let s = t[j] + m * sm2_n[j].to_uint64() + c2
      t[j - 1] = s & 0xFFFFFFFFUL
      c2 = s >> 32
    }
    let s8b = t[8] + c2
    t[7] = s8b & 0xFFFFFFFFUL
    t[8] = t[9] + (s8b >> 32)
    t[9] = 0UL
  }
  let res = FixedArray::make(8, 0U)
  for i = 0; i < 8; i = i + 1 {
    res[i] = t[i].to_uint()
  }
  let (sub, borrow) = raw_sub(res, sm2_n)
  let use_sub = if t[8] != 0UL || borrow == 0U { 1U } else { 0U }
  u256_ct_select(use_sub, { limbs: sub, }, { limbs: res, })
}

///|
fn sn_to_mont(a : U256) -> U256 {
  sn_mont_mul(a, { limbs: mont_r2_n, })
}

///|
fn sn_from_mont(a : U256) -> U256 {
  sn_mont_mul(a, u256_one())
}

///|
/// Scalar multiplication modulo n: computes (a * b) mod n.
fn sn_mul(a : U256, b : U256) -> U256 {
  let am = sn_to_mont(a)
  let bm = sn_to_mont(b)
  sn_from_mont(sn_mont_mul(am, bm))
}

///|
/// Constant-time scalar modular inverse in F_n: computes a^(n - 2) mod n.
fn sn_inv(a : U256) -> U256 {
  let exp : U256 = { limbs: sm2_n_minus_2, }
  let base = sn_to_mont(a)
  let mut acc = u256_from_limbs(mont_r1_n)
  for bit = 255; bit >= 0; bit = bit - 1 {
    acc = sn_mont_mul(acc, acc)
    let prod = sn_mont_mul(acc, base)
    acc = u256_ct_select(u256_get_bit(exp, bit), prod, acc)
  }
  sn_from_mont(acc)
}

///|
/// Checks 1 <= a <= n - 1.
fn sn_is_valid_nonzero(a : U256) -> Bool {
  !u256_is_zero(a) && u256_cmp_arr(a.limbs, sm2_n_minus_1) <= 0
}

///|
/// Checks 1 <= a <= n - 2 (required for SM2 private keys per GB/T 32918.1).
fn sn_is_valid_privkey(a : U256) -> Bool {
  !u256_is_zero(a) && u256_cmp_arr(a.limbs, sm2_n_minus_2) <= 0
}
