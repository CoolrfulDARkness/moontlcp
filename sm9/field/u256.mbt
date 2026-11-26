///|
/// BN256 curve parameter `t` (GB/T 38635.5-2020).
pub const BN_T : UInt64 = 0x600000000058f98aUL

///|
/// 256-bit unsigned integer stored in 4 little-endian 64-bit limbs.
#derive(Eq, Debug)
pub struct U256 {
  d0 : UInt64
  d1 : UInt64
  d2 : UInt64
  d3 : UInt64
}

///|
/// BN256 base field prime modulus `p` (GB/T 38635.5-2020):
/// `0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457d`.
pub let modulus_p : U256 = {
  d0: 0xe56f9b27e351457dUL,
  d1: 0x21f2934b1a7aeedbUL,
  d2: 0xd603ab4ff58ec745UL,
  d3: 0xb640000002a3a6f1UL,
}

///|
/// BN256 group order `N` (GB/T 38635.5-2020):
/// `0xb640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25`.
pub let order_n : U256 = {
  d0: 0xe56ee19cd69ecf25UL,
  d1: 0x49f2934b18ea8beeUL,
  d2: 0xd603ab4ff58ec744UL,
  d3: 0xb640000002a3a6f1UL,
}

///|
let all_ones : UInt64 = 0xFFFF_FFFF_FFFF_FFFFUL

///|
let mask32 : UInt64 = 0x0000_0000_FFFF_FFFFUL

///|
/// Converts a boolean into a constant-time 64-bit mask (`0xFFFF_FFFF_FFFF_FFFFUL` if true, else `0UL`).
pub fn ct_mask(cond : Bool) -> UInt64 {
  let bit : UInt64 = if cond { 1UL } else { 0UL }
  0UL - bit
}

///|
fn ct_is_zero_u64(x : UInt64) -> UInt64 {
  let nz = (x | (0UL - x)) >> 63
  nz - 1UL
}

///|
fn ct_select_u64(a : UInt64, b : UInt64, choice : UInt64) -> UInt64 {
  a ^ ((a ^ b) & choice)
}

///|
/// Add-with-carry: computes `a + b + carry`, returning `(sum, carry_out)`.
/// `carry` must be `0UL` or `1UL`.
pub fn adc(a : UInt64, b : UInt64, carry : UInt64) -> (UInt64, UInt64) {
  let s1 = a + b
  let c1 = ((a & b) | ((a | b) & (s1 ^ all_ones))) >> 63
  let s2 = s1 + carry
  let c2 = ((s1 & carry) | ((s1 | carry) & (s2 ^ all_ones))) >> 63
  (s2, c1 + c2)
}

///|
/// Subtract-with-borrow: computes `a - b - borrow`, returning `(diff, borrow_out)`.
/// `borrow` must be `0UL` or `1UL`.
pub fn sbb(a : UInt64, b : UInt64, borrow : UInt64) -> (UInt64, UInt64) {
  let d1 = a - b
  let b1 = (((a ^ all_ones) & b) | ((a ^ b ^ all_ones) & d1)) >> 63
  let d2 = d1 - borrow
  let b2 = (((d1 ^ all_ones) & borrow) | ((d1 ^ borrow ^ all_ones) & d2)) >> 63
  (d2, b1 + b2)
}

///|
fn mul_u64_wide(a : UInt64, b : UInt64) -> (UInt64, UInt64) {
  let a0 = a & mask32
  let a1 = a >> 32
  let b0 = b & mask32
  let b1 = b >> 32
  let p00 = a0 * b0
  let p01 = a0 * b1
  let p10 = a1 * b0
  let p11 = a1 * b1
  let mid = (p00 >> 32) + (p01 & mask32) + (p10 & mask32)
  let lo = (p00 & mask32) | (mid << 32)
  let hi = p11 + (p01 >> 32) + (p10 >> 32) + (mid >> 32)
  (lo, hi)
}

///|
/// Multiply-accumulate: computes `a + b * c + carry`, returning `(lo, hi)`.
pub fn mac(
  a : UInt64,
  b : UInt64,
  c : UInt64,
  carry : UInt64,
) -> (UInt64, UInt64) {
  let (plo, phi) = mul_u64_wide(b, c)
  let (s1, c1) = adc(plo, a, 0UL)
  let (s2, c2) = adc(s1, carry, 0UL)
  (s2, phi + c1 + c2)
}

///|
fn read_be_u64(b : BytesView, off : Int32) -> UInt64 {
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
fn write_u256_be(out : FixedArray[Byte], off : Int32, v : U256) -> Unit {
  write_be_u64(out, off, v.d3)
  write_be_u64(out, off + 8, v.d2)
  write_be_u64(out, off + 16, v.d1)
  write_be_u64(out, off + 24, v.d0)
}

///|
pub fn U256::zero() -> U256 {
  { d0: 0UL, d1: 0UL, d2: 0UL, d3: 0UL, }
}

///|
pub fn U256::one() -> U256 {
  { d0: 1UL, d1: 0UL, d2: 0UL, d3: 0UL, }
}

///|
pub fn U256::from_limbs(
  d0 : UInt64,
  d1 : UInt64,
  d2 : UInt64,
  d3 : UInt64,
) -> U256 {
  { d0, d1, d2, d3, }
}

///|
pub fn U256::from_u64(v : UInt64) -> U256 {
  { d0: v, d1: 0UL, d2: 0UL, d3: 0UL, }
}

///|
/// Decodes a 32-byte big-endian unsigned integer. Returns `None` if `b.length() != 32`.
pub fn U256::from_be_bytes(b : BytesView) -> U256? {
  if b.length() != 32 {
    return None
  }
  Some({
    d3: read_be_u64(b, 0),
    d2: read_be_u64(b, 8),
    d1: read_be_u64(b, 16),
    d0: read_be_u64(b, 24),
  })
}

///|
/// Encodes `self` as 32 big-endian bytes.
pub fn U256::to_be_bytes(self : U256) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(32, b'\x00')
  write_u256_be(out, 0, self)
  Bytes::makei(32, fn(i) { out[i] })
}

///|
/// Constant-time equality comparison.
pub fn U256::ct_eq(self : U256, other : U256) -> Bool {
  let diff = (self.d0 ^ other.d0) |
    (self.d1 ^ other.d1) |
    (self.d2 ^ other.d2) |
    (self.d3 ^ other.d3)
  ct_is_zero_u64(diff) != 0UL
}

///|
/// Constant-time selection: returns `a` if `choice == 0UL`, or `b` if `choice == 0xFFFF_FFFF_FFFF_FFFFUL`.
pub fn U256::ct_select(a : U256, b : U256, choice : UInt64) -> U256 {
  {
    d0: ct_select_u64(a.d0, b.d0, choice),
    d1: ct_select_u64(a.d1, b.d1, choice),
    d2: ct_select_u64(a.d2, b.d2, choice),
    d3: ct_select_u64(a.d3, b.d3, choice),
  }
}

///|
/// Constant-time zero check.
pub fn U256::is_zero(self : U256) -> Bool {
  let acc = self.d0 | self.d1 | self.d2 | self.d3
  ct_is_zero_u64(acc) != 0UL
}

///|
fn u256_sub_borrow(a : U256, b : U256) -> (U256, UInt64) {
  let (d0, brw) = sbb(a.d0, b.d0, 0UL)
  let (d1, brw) = sbb(a.d1, b.d1, brw)
  let (d2, brw) = sbb(a.d2, b.d2, brw)
  let (d3, brw) = sbb(a.d3, b.d3, brw)
  ({ d0, d1, d2, d3, }, brw)
}

///|
/// Constant-time unsigned comparison: returns `-1` if `self < other`, `0` if equal, `1` if `self > other`.
pub fn U256::cmp(self : U256, other : U256) -> Int32 {
  let (_, b1) = u256_sub_borrow(self, other)
  let (_, b2) = u256_sub_borrow(other, self)
  b2.to_int() - b1.to_int()
}

///|
/// Returns bit `i` (`0..255`, LSB = 0) as `0U` or `1U`. Out-of-range indices return `0U`.
pub fn U256::bit_at(self : U256, i : Int32) -> UInt32 {
  if i < 0 || i >= 256 {
    return 0U
  }
  let limb_idx = i >> 6
  let bit_idx = i & 63
  let limb = match limb_idx {
    0 => self.d0
    1 => self.d1
    2 => self.d2
    _ => self.d3
  }
  ((limb >> bit_idx) & 1UL).to_uint()
}

///|
/// Scalar field element modulo BN256 group order `N`, stored in 4x64-bit Montgomery form.
#derive(Eq, Debug)
pub struct Fn {
  priv d0 : UInt64
  priv d1 : UInt64
  priv d2 : UInt64
  priv d3 : UInt64
}

///|
let fn_n0 : UInt64 = 0xe56ee19cd69ecf25UL

///|
let fn_n1 : UInt64 = 0x49f2934b18ea8beeUL

///|
let fn_n2 : UInt64 = 0xd603ab4ff58ec744UL

///|
let fn_n3 : UInt64 = 0xb640000002a3a6f1UL

///|
/// `-N^{-1} mod 2^64`.
let fn_inv_n : UInt64 = 0x1d02662351974b53UL

///|
/// `R = 2^256 mod N` (Montgomery representation of `1`).
let fn_r : Fn = {
  d0: 0x1a911e63296130dbUL,
  d1: 0xb60d6cb4e7157411UL,
  d2: 0x29fc54b00a7138bbUL,
  d3: 0x49bffffffd5c590eUL,
}

///|
/// `R^2 mod N` (used to convert standard residues to Montgomery form).
let fn_r2 : Fn = {
  d0: 0x7598cd79cd750c35UL,
  d1: 0xe4a08110bb6daeabUL,
  d2: 0xbfee4bae7d78a1f9UL,
  d3: 0x8894f5d163695d0eUL,
}

///|
/// `N - 2` (for constant-time Fermat inversion `a^{N-2} mod N`).
let fn_n_minus_2 : U256 = {
  d0: 0xe56ee19cd69ecf23UL,
  d1: 0x49f2934b18ea8beeUL,
  d2: 0xd603ab4ff58ec744UL,
  d3: 0xb640000002a3a6f1UL,
}

///|
fn fn_sub_if_gte(
  t0 : UInt64,
  t1 : UInt64,
  t2 : UInt64,
  t3 : UInt64,
  t4 : UInt64,
) -> Fn {
  let (r0, brw) = sbb(t0, fn_n0, 0UL)
  let (r1, brw) = sbb(t1, fn_n1, brw)
  let (r2, brw) = sbb(t2, fn_n2, brw)
  let (r3, brw) = sbb(t3, fn_n3, brw)
  let (_, borrow) = sbb(t4, 0UL, brw)
  let mask = 0UL - borrow
  {
    d0: ct_select_u64(r0, t0, mask),
    d1: ct_select_u64(r1, t1, mask),
    d2: ct_select_u64(r2, t2, mask),
    d3: ct_select_u64(r3, t3, mask),
  }
}

///|
fn fn_mont_mul_raw(
  a0 : UInt64,
  a1 : UInt64,
  a2 : UInt64,
  a3 : UInt64,
  b0 : UInt64,
  b1 : UInt64,
  b2 : UInt64,
  b3 : UInt64,
) -> Fn {
  let mut t0 = 0UL
  let mut t1 = 0UL
  let mut t2 = 0UL
  let mut t3 = 0UL
  let mut t4 = 0UL
  // Iteration 0 (b0)
  let (s0, c) = mac(t0, a0, b0, 0UL)
  let (s1, c) = mac(t1, a1, b0, c)
  let (s2, c) = mac(t2, a2, b0, c)
  let (s3, c) = mac(t3, a3, b0, c)
  let (s4, s5) = adc(t4, c, 0UL)
  let q = s0 * fn_inv_n
  let (_, c) = mac(s0, q, fn_n0, 0UL)
  let (nt0, c) = mac(s1, q, fn_n1, c)
  let (nt1, c) = mac(s2, q, fn_n2, c)
  let (nt2, c) = mac(s3, q, fn_n3, c)
  let (nt3, c) = adc(s4, c, 0UL)
  t0 = nt0
  t1 = nt1
  t2 = nt2
  t3 = nt3
  t4 = s5 + c
  // Iteration 1 (b1)
  let (s0, c) = mac(t0, a0, b1, 0UL)
  let (s1, c) = mac(t1, a1, b1, c)
  let (s2, c) = mac(t2, a2, b1, c)
  let (s3, c) = mac(t3, a3, b1, c)
  let (s4, s5) = adc(t4, c, 0UL)
  let q = s0 * fn_inv_n
  let (_, c) = mac(s0, q, fn_n0, 0UL)
  let (nt0, c) = mac(s1, q, fn_n1, c)
  let (nt1, c) = mac(s2, q, fn_n2, c)
  let (nt2, c) = mac(s3, q, fn_n3, c)
  let (nt3, c) = adc(s4, c, 0UL)
  t0 = nt0
  t1 = nt1
  t2 = nt2
  t3 = nt3
  t4 = s5 + c
  // Iteration 2 (b2)
  let (s0, c) = mac(t0, a0, b2, 0UL)
  let (s1, c) = mac(t1, a1, b2, c)
  let (s2, c) = mac(t2, a2, b2, c)
  let (s3, c) = mac(t3, a3, b2, c)
  let (s4, s5) = adc(t4, c, 0UL)
  let q = s0 * fn_inv_n
  let (_, c) = mac(s0, q, fn_n0, 0UL)
  let (nt0, c) = mac(s1, q, fn_n1, c)
  let (nt1, c) = mac(s2, q, fn_n2, c)
  let (nt2, c) = mac(s3, q, fn_n3, c)
  let (nt3, c) = adc(s4, c, 0UL)
  t0 = nt0
  t1 = nt1
  t2 = nt2
  t3 = nt3
  t4 = s5 + c
  // Iteration 3 (b3)
  let (s0, c) = mac(t0, a0, b3, 0UL)
  let (s1, c) = mac(t1, a1, b3, c)
  let (s2, c) = mac(t2, a2, b3, c)
  let (s3, c) = mac(t3, a3, b3, c)
  let (s4, s5) = adc(t4, c, 0UL)
  let q = s0 * fn_inv_n
  let (_, c) = mac(s0, q, fn_n0, 0UL)
  let (nt0, c) = mac(s1, q, fn_n1, c)
  let (nt1, c) = mac(s2, q, fn_n2, c)
  let (nt2, c) = mac(s3, q, fn_n3, c)
  let (nt3, c) = adc(s4, c, 0UL)
  t0 = nt0
  t1 = nt1
  t2 = nt2
  t3 = nt3
  t4 = s5 + c
  fn_sub_if_gte(t0, t1, t2, t3, t4)
}

///|
fn fn_mont_reduce(a : Fn) -> U256 {
  let mut t0 = a.d0
  let mut t1 = a.d1
  let mut t2 = a.d2
  let mut t3 = a.d3
  let mut t4 = 0UL
  for _i = 0; _i < 4; _i = _i + 1 {
    let q = t0 * fn_inv_n
    let (_, c) = mac(t0, q, fn_n0, 0UL)
    let (nt0, c) = mac(t1, q, fn_n1, c)
    let (nt1, c) = mac(t2, q, fn_n2, c)
    let (nt2, c) = mac(t3, q, fn_n3, c)
    let (nt3, nt4) = adc(t4, c, 0UL)
    t0 = nt0
    t1 = nt1
    t2 = nt2
    t3 = nt3
    t4 = nt4
  }
  let r = fn_sub_if_gte(t0, t1, t2, t3, t4)
  { d0: r.d0, d1: r.d1, d2: r.d2, d3: r.d3, }
}

///|
pub fn Fn::zero() -> Fn {
  { d0: 0UL, d1: 0UL, d2: 0UL, d3: 0UL, }
}

///|
pub fn Fn::one() -> Fn {
  fn_r
}

///|
pub fn Fn::from_u64(v : UInt64) -> Fn {
  fn_mont_mul_raw(v, 0UL, 0UL, 0UL, fn_r2.d0, fn_r2.d1, fn_r2.d2, fn_r2.d3)
}

///|
/// Reduces any 256-bit unsigned integer modulo `N`.
pub fn Fn::from_u256_mod(v : U256) -> Fn {
  // Since N > 2^255, 2*N > 2^256, so one conditional subtraction reduces any U256.
  let red = fn_sub_if_gte(v.d0, v.d1, v.d2, v.d3, 0UL)
  fn_mont_mul_raw(
    red.d0,
    red.d1,
    red.d2,
    red.d3,
    fn_r2.d0,
    fn_r2.d1,
    fn_r2.d2,
    fn_r2.d3,
  )
}

///|
/// Strictly decodes a 32-byte big-endian scalar in `[0, N - 1]`.
pub fn Fn::from_be_bytes_strict(b : BytesView) -> Fn? {
  match U256::from_be_bytes(b) {
    None => None
    Some(v) =>
      if v.cmp(order_n) < 0 {
        Some(
          fn_mont_mul_raw(
            v.d0,
            v.d1,
            v.d2,
            v.d3,
            fn_r2.d0,
            fn_r2.d1,
            fn_r2.d2,
            fn_r2.d3,
          ),
        )
      } else {
        None
      }
  }
}

///|
/// Strictly decodes a 32-byte big-endian non-zero scalar in `[1, N - 1]`.
pub fn Fn::from_be_bytes_nonzero(b : BytesView) -> Fn? {
  match Fn::from_be_bytes_strict(b) {
    None => None
    Some(x) => if x.is_zero() { None } else { Some(x) }
  }
}

///|
/// Decodes big-endian bytes of any length and reduces modulo `N`.
pub fn Fn::from_be_bytes_mod(b : BytesView) -> Fn {
  if b.length() == 32 {
    match U256::from_be_bytes(b) {
      Some(v) => return Fn::from_u256_mod(v)
      None => ()
    }
  }
  let base256 = Fn::from_u64(256UL)
  let mut acc = Fn::zero()
  for i = 0; i < b.length(); i = i + 1 {
    acc = acc.mul(base256).add(Fn::from_u64(b[i].to_uint64()))
  }
  acc
}

///|
pub fn Fn::to_u256(self : Fn) -> U256 {
  fn_mont_reduce(self)
}

///|
pub fn Fn::to_be_bytes(self : Fn) -> Bytes {
  self.to_u256().to_be_bytes()
}

///|
pub fn Fn::is_zero(self : Fn) -> Bool {
  let acc = self.d0 | self.d1 | self.d2 | self.d3
  ct_is_zero_u64(acc) != 0UL
}

///|
pub fn Fn::is_one(self : Fn) -> Bool {
  self.ct_eq(fn_r)
}

///|
pub fn Fn::ct_eq(self : Fn, other : Fn) -> Bool {
  let diff = (self.d0 ^ other.d0) |
    (self.d1 ^ other.d1) |
    (self.d2 ^ other.d2) |
    (self.d3 ^ other.d3)
  ct_is_zero_u64(diff) != 0UL
}

///|
pub fn Fn::ct_select(a : Fn, b : Fn, choice : UInt64) -> Fn {
  {
    d0: ct_select_u64(a.d0, b.d0, choice),
    d1: ct_select_u64(a.d1, b.d1, choice),
    d2: ct_select_u64(a.d2, b.d2, choice),
    d3: ct_select_u64(a.d3, b.d3, choice),
  }
}

///|
pub fn Fn::add(self : Fn, other : Fn) -> Fn {
  let (s0, c) = adc(self.d0, other.d0, 0UL)
  let (s1, c) = adc(self.d1, other.d1, c)
  let (s2, c) = adc(self.d2, other.d2, c)
  let (s3, carry) = adc(self.d3, other.d3, c)
  fn_sub_if_gte(s0, s1, s2, s3, carry)
}

///|
pub fn Fn::sub(self : Fn, other : Fn) -> Fn {
  let (d0, brw) = sbb(self.d0, other.d0, 0UL)
  let (d1, brw) = sbb(self.d1, other.d1, brw)
  let (d2, brw) = sbb(self.d2, other.d2, brw)
  let (d3, borrow) = sbb(self.d3, other.d3, brw)
  let mask = 0UL - borrow
  let (r0, c) = adc(d0, fn_n0 & mask, 0UL)
  let (r1, c) = adc(d1, fn_n1 & mask, c)
  let (r2, c) = adc(d2, fn_n2 & mask, c)
  let (r3, _) = adc(d3, fn_n3 & mask, c)
  { d0: r0, d1: r1, d2: r2, d3: r3, }
}

///|
pub fn Fn::neg(self : Fn) -> Fn {
  Fn::zero().sub(self)
}

///|
pub fn Fn::mul(self : Fn, other : Fn) -> Fn {
  fn_mont_mul_raw(
    self.d0,
    self.d1,
    self.d2,
    self.d3,
    other.d0,
    other.d1,
    other.d2,
    other.d3,
  )
}

///|
pub fn Fn::sqr(self : Fn) -> Fn {
  self.mul(self)
}

///|
/// Constant-time modular inversion via Fermat's little theorem `self^{N-2} mod N`.
/// Returns `None` if `self == 0`.
pub fn Fn::inv(self : Fn) -> Fn? {
  if self.is_zero() {
    return None
  }
  let mut res = Fn::one()
  for i = 255; i >= 0; i = i - 1 {
    res = res.sqr()
    if fn_n_minus_2.bit_at(i) == 1U {
      res = res.mul(self)
    }
  }
  Some(res)
}
