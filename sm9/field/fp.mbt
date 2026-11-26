///|
/// Base prime field element `Fp` modulo BN256 `p`, stored in 4x64-bit Montgomery form (`a * R mod p`).
#derive(Eq, Debug)
pub struct Fp {
  priv d0 : UInt64
  priv d1 : UInt64
  priv d2 : UInt64
  priv d3 : UInt64
}

///|
let fp_p0 : UInt64 = 0xe56f9b27e351457dUL

///|
let fp_p1 : UInt64 = 0x21f2934b1a7aeedbUL

///|
let fp_p2 : UInt64 = 0xd603ab4ff58ec745UL

///|
let fp_p3 : UInt64 = 0xb640000002a3a6f1UL

///|
/// `-p^{-1} mod 2^64`.
let fp_inv_p : UInt64 = 0x892bc42c2f2ee42bUL

///|
/// `R = 2^256 mod p` (Montgomery representation of `1`).
let fp_r : Fp = {
  d0: 0x1a9064d81caeba83UL,
  d1: 0xde0d6cb4e5851124UL,
  d2: 0x29fc54b00a7138baUL,
  d3: 0x49bffffffd5c590eUL,
}

///|
/// `R^2 mod p` (used to convert standard residues to Montgomery form).
let fp_r2 : Fp = {
  d0: 0x27dea312b417e2d2UL,
  d1: 0x88f8105fae1a5d3fUL,
  d2: 0xe479b522d6706e7bUL,
  d3: 0x2ea795a656f62fbdUL,
}

///|
/// `Mont(5) = 5 * R mod p` (curve equation constant `b = 5`).
let fp_b5 : Fp = {
  d0: 0xb9f2c1e8c8c71995UL,
  d1: 0x125df8f246a377fcUL,
  d2: 0x25e650d049188d1cUL,
  d3: 0x043fffffed866f63UL,
}

///|
/// `p - 2` (for constant-time Fermat inversion `a^{p-2} mod p`).
let fp_p_minus_2 : U256 = {
  d0: 0xe56f9b27e351457bUL,
  d1: 0x21f2934b1a7aeedbUL,
  d2: 0xd603ab4ff58ec745UL,
  d3: 0xb640000002a3a6f1UL,
}

///|
/// `(p - 5) / 8` (for Atkin square root since `p == 5 mod 8`).
let fp_p_minus_5_div_8 : U256 = {
  d0: 0x7cadf364fc6a28afUL,
  d1: 0xa43e5269634f5ddbUL,
  d2: 0x3ac07569feb1d8e8UL,
  d3: 0x16c80000005474deUL,
}

///|
fn fp_sub_if_gte(
  t0 : UInt64,
  t1 : UInt64,
  t2 : UInt64,
  t3 : UInt64,
  t4 : UInt64,
) -> Fp {
  let (r0, brw) = sbb(t0, fp_p0, 0UL)
  let (r1, brw) = sbb(t1, fp_p1, brw)
  let (r2, brw) = sbb(t2, fp_p2, brw)
  let (r3, brw) = sbb(t3, fp_p3, brw)
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
fn fp_mont_mul_raw(
  a0 : UInt64,
  a1 : UInt64,
  a2 : UInt64,
  a3 : UInt64,
  b0 : UInt64,
  b1 : UInt64,
  b2 : UInt64,
  b3 : UInt64,
) -> Fp {
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
  let q = s0 * fp_inv_p
  let (_, c) = mac(s0, q, fp_p0, 0UL)
  let (nt0, c) = mac(s1, q, fp_p1, c)
  let (nt1, c) = mac(s2, q, fp_p2, c)
  let (nt2, c) = mac(s3, q, fp_p3, c)
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
  let q = s0 * fp_inv_p
  let (_, c) = mac(s0, q, fp_p0, 0UL)
  let (nt0, c) = mac(s1, q, fp_p1, c)
  let (nt1, c) = mac(s2, q, fp_p2, c)
  let (nt2, c) = mac(s3, q, fp_p3, c)
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
  let q = s0 * fp_inv_p
  let (_, c) = mac(s0, q, fp_p0, 0UL)
  let (nt0, c) = mac(s1, q, fp_p1, c)
  let (nt1, c) = mac(s2, q, fp_p2, c)
  let (nt2, c) = mac(s3, q, fp_p3, c)
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
  let q = s0 * fp_inv_p
  let (_, c) = mac(s0, q, fp_p0, 0UL)
  let (nt0, c) = mac(s1, q, fp_p1, c)
  let (nt1, c) = mac(s2, q, fp_p2, c)
  let (nt2, c) = mac(s3, q, fp_p3, c)
  let (nt3, c) = adc(s4, c, 0UL)
  t0 = nt0
  t1 = nt1
  t2 = nt2
  t3 = nt3
  t4 = s5 + c
  fp_sub_if_gte(t0, t1, t2, t3, t4)
}

///|
fn fp_mont_reduce(a : Fp) -> U256 {
  let mut t0 = a.d0
  let mut t1 = a.d1
  let mut t2 = a.d2
  let mut t3 = a.d3
  let mut t4 = 0UL
  for _i = 0; _i < 4; _i = _i + 1 {
    let q = t0 * fp_inv_p
    let (_, c) = mac(t0, q, fp_p0, 0UL)
    let (nt0, c) = mac(t1, q, fp_p1, c)
    let (nt1, c) = mac(t2, q, fp_p2, c)
    let (nt2, c) = mac(t3, q, fp_p3, c)
    let (nt3, nt4) = adc(t4, c, 0UL)
    t0 = nt0
    t1 = nt1
    t2 = nt2
    t3 = nt3
    t4 = nt4
  }
  let r = fp_sub_if_gte(t0, t1, t2, t3, t4)
  { d0: r.d0, d1: r.d1, d2: r.d2, d3: r.d3, }
}

///|
pub fn Fp::zero() -> Fp {
  { d0: 0UL, d1: 0UL, d2: 0UL, d3: 0UL, }
}

///|
pub fn Fp::one() -> Fp {
  fp_r
}

///|
/// Returns the curve constant `b = 5` in Montgomery form.
pub fn Fp::b_const() -> Fp {
  fp_b5
}

///|
/// Constructs an `Fp` directly from precomputed 4x64-bit little-endian Montgomery limbs (`< p`).
pub fn Fp::from_raw_mont(
  d0 : UInt64,
  d1 : UInt64,
  d2 : UInt64,
  d3 : UInt64,
) -> Fp {
  { d0, d1, d2, d3, }
}

///|
pub fn Fp::from_u64(v : UInt64) -> Fp {
  fp_mont_mul_raw(v, 0UL, 0UL, 0UL, fp_r2.d0, fp_r2.d1, fp_r2.d2, fp_r2.d3)
}

///|
/// Converts any 256-bit unsigned integer into `Fp` (reducing modulo `p`).
pub fn Fp::from_u256(v : U256) -> Fp {
  // Since p > 2^255, 2*p > 2^256, so one conditional subtraction reduces any U256.
  let red = fp_sub_if_gte(v.d0, v.d1, v.d2, v.d3, 0UL)
  fp_mont_mul_raw(
    red.d0,
    red.d1,
    red.d2,
    red.d3,
    fp_r2.d0,
    fp_r2.d1,
    fp_r2.d2,
    fp_r2.d3,
  )
}

///|
/// Strictly decodes 32 big-endian bytes into `Fp`. Rejects non-32-byte inputs or values `>= p`.
pub fn Fp::from_be_bytes_strict(b : BytesView) -> Fp? {
  match U256::from_be_bytes(b) {
    None => None
    Some(v) =>
      if v.cmp(modulus_p) < 0 {
        Some(
          fp_mont_mul_raw(
            v.d0,
            v.d1,
            v.d2,
            v.d3,
            fp_r2.d0,
            fp_r2.d1,
            fp_r2.d2,
            fp_r2.d3,
          ),
        )
      } else {
        None
      }
  }
}

///|
/// Converts `self` out of Montgomery form to its canonical `U256` in `[0, p - 1]`.
pub fn Fp::to_u256(self : Fp) -> U256 {
  fp_mont_reduce(self)
}

///|
/// Encodes `self` as 32 big-endian bytes (`FE2OS`).
pub fn Fp::to_be_bytes(self : Fp) -> Bytes {
  self.to_u256().to_be_bytes()
}

///|
fn Fp::write_be_bytes_into(
  self : Fp,
  out : FixedArray[Byte],
  off : Int32,
) -> Unit {
  write_u256_be(out, off, self.to_u256())
}

///|
/// Constant-time zero mask: returns `0xFFFF_FFFF_FFFF_FFFFUL` if `self == 0`, else `0UL`.
/// Implemented purely via bitwise operations without converting through `Bool` or `if`.
pub fn Fp::is_zero_mask(self : Fp) -> UInt64 {
  ct_is_zero_u64(self.d0 | self.d1 | self.d2 | self.d3)
}

///|
pub fn Fp::is_zero(self : Fp) -> Bool {
  self.is_zero_mask() != 0UL
}

///|
pub fn Fp::is_one(self : Fp) -> Bool {
  self.ct_eq(fp_r)
}

///|
pub fn Fp::ct_eq(self : Fp, other : Fp) -> Bool {
  let diff = (self.d0 ^ other.d0) |
    (self.d1 ^ other.d1) |
    (self.d2 ^ other.d2) |
    (self.d3 ^ other.d3)
  ct_is_zero_u64(diff) != 0UL
}

///|
pub fn Fp::ct_select(a : Fp, b : Fp, choice : UInt64) -> Fp {
  {
    d0: ct_select_u64(a.d0, b.d0, choice),
    d1: ct_select_u64(a.d1, b.d1, choice),
    d2: ct_select_u64(a.d2, b.d2, choice),
    d3: ct_select_u64(a.d3, b.d3, choice),
  }
}

///|
pub fn Fp::add(self : Fp, other : Fp) -> Fp {
  let (s0, c) = adc(self.d0, other.d0, 0UL)
  let (s1, c) = adc(self.d1, other.d1, c)
  let (s2, c) = adc(self.d2, other.d2, c)
  let (s3, carry) = adc(self.d3, other.d3, c)
  fp_sub_if_gte(s0, s1, s2, s3, carry)
}

///|
pub fn Fp::sub(self : Fp, other : Fp) -> Fp {
  let (d0, brw) = sbb(self.d0, other.d0, 0UL)
  let (d1, brw) = sbb(self.d1, other.d1, brw)
  let (d2, brw) = sbb(self.d2, other.d2, brw)
  let (d3, borrow) = sbb(self.d3, other.d3, brw)
  let mask = 0UL - borrow
  let (r0, c) = adc(d0, fp_p0 & mask, 0UL)
  let (r1, c) = adc(d1, fp_p1 & mask, c)
  let (r2, c) = adc(d2, fp_p2 & mask, c)
  let (r3, _) = adc(d3, fp_p3 & mask, c)
  { d0: r0, d1: r1, d2: r2, d3: r3, }
}

///|
pub fn Fp::neg(self : Fp) -> Fp {
  Fp::zero().sub(self)
}

///|
pub fn Fp::double(self : Fp) -> Fp {
  self.add(self)
}

///|
pub fn Fp::triple(self : Fp) -> Fp {
  self.double().add(self)
}

///|
pub fn Fp::mul_by_5(self : Fp) -> Fp {
  self.double().double().add(self)
}

///|
pub fn Fp::mul(self : Fp, other : Fp) -> Fp {
  fp_mont_mul_raw(
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
pub fn Fp::sqr(self : Fp) -> Fp {
  self.mul(self)
}

///|
/// Constant-time exponentiation `self^exp mod p` for arbitrary 256-bit exponents.
pub fn Fp::pow(self : Fp, exp : U256) -> Fp {
  let mut res = Fp::one()
  for i = 255; i >= 0; i = i - 1 {
    res = res.sqr()
    let prod = res.mul(self)
    let mask = 0UL - exp.bit_at(i).to_uint64()
    res = Fp::ct_select(res, prod, mask)
  }
  res
}

///|
/// Constant-time Fermat inversion `self^{p-2} mod p`. Returns `0` for `self == 0`.
pub fn Fp::inv(self : Fp) -> Fp {
  let mut res = Fp::one()
  for i = 255; i >= 0; i = i - 1 {
    res = res.sqr()
    if fp_p_minus_2.bit_at(i) == 1U {
      res = res.mul(self)
    }
  }
  res
}

///|
/// Checked modular inversion returning `None` when `self == 0`.
pub fn Fp::inv_checked(self : Fp) -> Fp? {
  if self.is_zero() {
    None
  } else {
    Some(self.inv())
  }
}

///|
/// Square root in `Fp` using Atkin's method (since `p == 5 mod 8`).
/// Returns `None` if `self` is a quadratic non-residue.
pub fn Fp::sqrt(self : Fp) -> Fp? {
  if self.is_zero() {
    return Some(Fp::zero())
  }
  let a2 = self.double()
  let mut v = Fp::one()
  for i = 255; i >= 0; i = i - 1 {
    v = v.sqr()
    if fp_p_minus_5_div_8.bit_at(i) == 1U {
      v = v.mul(a2)
    }
  }
  let i_val = a2.mul(v.sqr())
  let r = self.mul(v).mul(i_val.sub(Fp::one()))
  if r.sqr().ct_eq(self) {
    Some(r)
  } else {
    None
  }
}

///|
/// Frobenius constant `GAMMA_11 = (-2)^{(p-1)/12} mod p` (Montgomery form).
pub fn gamma_11() -> Fp {
  Fp::from_raw_mont(
    0x1a98dfbd4575299fUL, 0x9ec8547b245c54fdUL, 0xf51f5eac13df846cUL, 0x9ef74015d5a16393UL,
  )
}

///|
/// Frobenius constant `GAMMA_12 = (-2)^{(p-1)/6} mod p` (Montgomery form).
pub fn gamma_12() -> Fp {
  Fp::from_raw_mont(
    0xb626197dce4736caUL, 0x08296b3557ed0186UL, 0x9c705db2fd91512aUL, 0x1c753e748601c992UL,
  )
}

///|
/// Frobenius constant `GAMMA_13 = (-2)^{(p-1)/4} mod p` (Montgomery form).
pub fn gamma_13() -> Fp {
  Fp::from_raw_mont(
    0x39b4ef0f3ee72529UL, 0xdb043bf508582782UL, 0xb8554ab054ac91e3UL, 0x9848eec25498cab5UL,
  )
}

///|
/// Frobenius constant `GAMMA_14 = (-2)^{(p-1)/3} mod p` (Montgomery form).
pub fn gamma_14() -> Fp {
  Fp::from_raw_mont(
    0x81054fcd94e9c1c4UL, 0x4c0e91cb8ce2df3eUL, 0x4877b452e8aedfb4UL, 0x88f53e748b491776UL,
  )
}

///|
/// Frobenius constant `GAMMA_15 = (-2)^{5(p-1)/12} mod p` (Montgomery form).
pub fn gamma_15() -> Fp {
  Fp::from_raw_mont(
    0x048baa79dcc34107UL, 0x5e2e7ac4fe76c161UL, 0x99399754365bd4bcUL, 0xaf91aeac819b0e13UL,
  )
}

///|
/// Frobenius constant `GAMMA_21 = t^{p^2-1} = GAMMA_12` (Montgomery form).
pub fn gamma_21() -> Fp {
  Fp::from_raw_mont(
    0xb626197dce4736caUL, 0x08296b3557ed0186UL, 0x9c705db2fd91512aUL, 0x1c753e748601c992UL,
  )
}

///|
/// Frobenius constant `GAMMA_22 = s^{p^2-1} = GAMMA_14` (Montgomery form).
pub fn gamma_22() -> Fp {
  Fp::from_raw_mont(
    0x81054fcd94e9c1c4UL, 0x4c0e91cb8ce2df3eUL, 0x4877b452e8aedfb4UL, 0x88f53e748b491776UL,
  )
}

///|
/// Frobenius constant `GAMMA_23 = v^{p^2-1} = p - 1` (Montgomery form).
pub fn gamma_23() -> Fp {
  Fp::from_raw_mont(
    0xcadf364fc6a28afaUL, 0x43e5269634f5ddb7UL, 0xac07569feb1d8e8aUL, 0x6c80000005474de3UL,
  )
}

///|
/// Frobenius constant `GAMMA_24 = s^{2(p^2-1)} = (-2)^{2(p-1)/3}` (Montgomery form).
pub fn gamma_24() -> Fp {
  Fp::from_raw_mont(
    0x2f4981aa150a0eb3UL, 0x19c92815c28ded55UL, 0x39934d9cf7fd761bUL, 0x99cac18b7ca1dd5fUL,
  )
}

///|
/// Twist Frobenius constant `TWIST_FROB_X1 = u^{-(p-1)/3} = GAMMA_12^{-1}` (Montgomery form).
pub fn twist_frob_x1() -> Fp {
  Fp::from_raw_mont(
    0x646a4b5a4e6783b9UL, 0xd5e4017f8d980f9dUL, 0x8d8bf6fd0cdfe790UL, 0x2d4ac18b775a8f7bUL,
  )
}

///|
/// Twist Frobenius constant `TWIST_FROB_Y1 = u^{-(p-1)/2} = GAMMA_13^{-1}` (Montgomery form).
pub fn twist_frob_y1() -> Fp {
  Fp::from_raw_mont(
    0xabbaac18a46a2054UL, 0x46ee57561222c759UL, 0x1dae609fa0e23561UL, 0x1df7113dae0adc3cUL,
  )
}

///|
/// Twist Frobenius constant `TWIST_FROB_X2 = u^{-(p^2-1)/3} = GAMMA_24` (Montgomery form).
pub fn twist_frob_x2() -> Fp {
  Fp::from_raw_mont(
    0x2f4981aa150a0eb3UL, 0x19c92815c28ded55UL, 0x39934d9cf7fd761bUL, 0x99cac18b7ca1dd5fUL,
  )
}

///|
/// Twist Frobenius constant `TWIST_FROB_Y2 = u^{-(p^2-1)/2} = p - 1` (Montgomery form).
pub fn twist_frob_y2() -> Fp {
  Fp::from_raw_mont(
    0xcadf364fc6a28afaUL, 0x43e5269634f5ddb7UL, 0xac07569feb1d8e8aUL, 0x6c80000005474de3UL,
  )
}
