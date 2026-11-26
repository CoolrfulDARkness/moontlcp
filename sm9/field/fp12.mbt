///|
/// Twelfth-degree extension field `Fp12 = Fp6[t] / (t^2 - s)` representing `c0 + c1*t`.
#derive(Eq, Debug)
pub struct Fp12 {
  c0 : Fp6
  c1 : Fp6
}

///|
/// NAF representation of `BN_T = 0x600000000058f98a` (LSB to MSB, 64 entries).
let bn_t_naf : FixedArray[Int32] = [
  0, 1, 0, 1, 0, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 1, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 1,
]

///|
pub fn Fp12::new(c0 : Fp6, c1 : Fp6) -> Fp12 {
  { c0, c1, }
}

///|
pub fn Fp12::zero() -> Fp12 {
  { c0: Fp6::zero(), c1: Fp6::zero(), }
}

///|
pub fn Fp12::one() -> Fp12 {
  { c0: Fp6::one(), c1: Fp6::zero(), }
}

///|
pub fn Fp12::is_zero(self : Fp12) -> Bool {
  self.c0.is_zero() && self.c1.is_zero()
}

///|
pub fn Fp12::is_one(self : Fp12) -> Bool {
  self.c0.is_one() && self.c1.is_zero()
}

///|
pub fn Fp12::ct_eq(self : Fp12, other : Fp12) -> Bool {
  let m0 = ct_mask(self.c0.ct_eq(other.c0))
  let m1 = ct_mask(self.c1.ct_eq(other.c1))
  (m0 & m1) != 0UL
}

///|
pub fn Fp12::ct_select(a : Fp12, b : Fp12, choice : UInt64) -> Fp12 {
  {
    c0: Fp6::ct_select(a.c0, b.c0, choice),
    c1: Fp6::ct_select(a.c1, b.c1, choice),
  }
}

///|
pub fn Fp12::add(self : Fp12, other : Fp12) -> Fp12 {
  { c0: self.c0.add(other.c0), c1: self.c1.add(other.c1), }
}

///|
pub fn Fp12::sub(self : Fp12, other : Fp12) -> Fp12 {
  { c0: self.c0.sub(other.c0), c1: self.c1.sub(other.c1), }
}

///|
pub fn Fp12::neg(self : Fp12) -> Fp12 {
  { c0: self.c0.neg(), c1: self.c1.neg(), }
}

///|
/// Karatsuba multiplication in `Fp12` with `t^2 = s`.
pub fn Fp12::mul(self : Fp12, other : Fp12) -> Fp12 {
  let v0 = self.c0.mul(other.c0)
  let v1 = self.c1.mul(other.c1)
  let c0 = v0.add(v1.mul_by_s())
  let c1 = self.c0.add(self.c1).mul(other.c0.add(other.c1)).sub(v0).sub(v1)
  { c0, c1, }
}

///|
/// Complex squaring in `Fp12` using 2 `Fp6` multiplications.
pub fn Fp12::sqr(self : Fp12) -> Fp12 {
  let ab = self.c0.mul(self.c1)
  let c0 = self.c0
    .add(self.c1)
    .mul(self.c0.add(self.c1.mul_by_s()))
    .sub(ab)
    .sub(ab.mul_by_s())
  let c1 = ab.double()
  { c0, c1, }
}

///|
/// Squaring in `Fp4 = Fp2[v] / (v^2 - u)` used by Granger-Scott cyclotomic squaring.
fn fp4_sqr(x0 : Fp2, x1 : Fp2) -> (Fp2, Fp2) {
  let t0 = x0.sqr()
  let t1 = x1.sqr()
  let r0 = t0.add(t1.mul_by_u())
  let r1 = x0.add(x1).sqr().sub(t0).sub(t1)
  (r0, r1)
}

///|
/// Granger-Scott fast squaring for elements in the cyclotomic subgroup `G_{Phi_6}(Fp2)`.
pub fn Fp12::cyclotomic_sqr(self : Fp12) -> Fp12 {
  let a0 = self.c0.c0
  let a1 = self.c0.c1
  let a2 = self.c0.c2
  let b0 = self.c1.c0
  let b1 = self.c1.c1
  let b2 = self.c1.c2
  let (t00, t01) = fp4_sqr(a0, b1)
  let new_a0 = t00.sub(a0).double().add(t00)
  let new_b1 = t01.add(b1).double().add(t01)
  let (t10, t11) = fp4_sqr(b0, a2)
  let new_a1 = t10.sub(a1).double().add(t10)
  let new_b2 = t11.add(b2).double().add(t11)
  let (t20, t21) = fp4_sqr(a1, b2)
  let s20 = t21.mul_by_u()
  let new_b0 = s20.add(b0).double().add(s20)
  let new_a2 = t20.sub(a2).double().add(t20)
  {
    c0: Fp6::new(new_a0, new_a1, new_a2),
    c1: Fp6::new(new_b0, new_b1, new_b2),
  }
}

///|
/// Sparse multiplication by a Miller line function `l = (a + b*s) + (c*s)*t`.
pub fn Fp12::mul_by_014(self : Fp12, a : Fp2, b : Fp2, c : Fp2) -> Fp12 {
  let t0 = self.c0.mul_by_01(a, b)
  let t1 = self.c1.mul_by_1(c)
  let c0 = t0.add(t1.mul_by_s())
  let c1 = self.c0.add(self.c1).mul_by_01(a, b.add(c)).sub(t0).sub(t1)
  { c0, c1, }
}

///|
/// Conjugation `self^{p^6} = c0 - c1*t` (equals `self^{-1}` in the cyclotomic subgroup).
pub fn Fp12::conjugate(self : Fp12) -> Fp12 {
  { c0: self.c0, c1: self.c1.neg(), }
}

///|
/// Constant-time inversion in `Fp12`. Returns `0` for `self == 0`.
pub fn Fp12::inv(self : Fp12) -> Fp12 {
  let norm = self.c0.sqr().sub(self.c1.sqr().mul_by_s())
  let t = norm.inv()
  { c0: self.c0.mul(t), c1: self.c1.neg().mul(t), }
}

///|
/// Checked inversion returning `None` when `self == 0`.
pub fn Fp12::inv_checked(self : Fp12) -> Fp12? {
  if self.is_zero() {
    None
  } else {
    Some(self.inv())
  }
}

///|
/// Frobenius endomorphism `self^p` in `Fp12`.
pub fn Fp12::frobenius_p(self : Fp12) -> Fp12 {
  { c0: self.c0.frobenius_p(), c1: self.c1.frobenius_p().mul_fp(gamma_11()), }
}

///|
/// Frobenius endomorphism `self^{p^2}` in `Fp12`.
pub fn Fp12::frobenius_p2(self : Fp12) -> Fp12 {
  { c0: self.c0.frobenius_p2(), c1: self.c1.frobenius_p2().mul_fp(gamma_21()), }
}

///|
/// Frobenius endomorphism `self^{p^3}` in `Fp12`.
pub fn Fp12::frobenius_p3(self : Fp12) -> Fp12 {
  self.frobenius_p2().frobenius_p()
}

///|
/// Checks whether `self` belongs to the cyclotomic subgroup `G_{Phi_6}(Fp2)`.
/// Verifies `self != 0`, `self^{p^6} * self == 1`, and `self^{p^4 + 1} == self^{p^2}`
/// (equivalently `self^{p^4 - p^2 + 1} == 1`).
pub fn Fp12::is_in_cyclotomic_subgroup(self : Fp12) -> Bool {
  if self.is_zero() || !self.conjugate().mul(self).is_one() {
    return false
  }
  let fp2 = self.frobenius_p2()
  fp2.frobenius_p2().mul(self).ct_eq(fp2)
}

///|
/// Constant-time exponentiation `self^exp` for arbitrary 256-bit exponents.
pub fn Fp12::pow_u256(self : Fp12, exp : U256) -> Fp12 {
  let mut res = Fp12::one()
  for i = 255; i >= 0; i = i - 1 {
    res = res.sqr()
    let prod = res.mul(self)
    let mask = 0UL - exp.bit_at(i).to_uint64()
    res = Fp12::ct_select(res, prod, mask)
  }
  res
}

///|
/// Constant-time exponentiation `self^exp` for cyclotomic subgroup elements using `cyclotomic_sqr`.
pub fn Fp12::cyclotomic_pow_u256(self : Fp12, exp : U256) -> Fp12 {
  let mut res = Fp12::one()
  for i = 255; i >= 0; i = i - 1 {
    res = res.cyclotomic_sqr()
    let prod = res.mul(self)
    let mask = 0UL - exp.bit_at(i).to_uint64()
    res = Fp12::ct_select(res, prod, mask)
  }
  res
}

///|
/// Fast exponentiation `self^BN_T` for cyclotomic subgroup elements using `BN_T` NAF,
/// `cyclotomic_sqr`, and `conjugate`.
pub fn Fp12::cyclotomic_pow_t(self : Fp12) -> Fp12 {
  let f_inv = self.conjugate()
  // MSB at index 63 of bn_t_naf is +1
  let mut res = self
  for i = 62; i >= 0; i = i - 1 {
    res = res.cyclotomic_sqr()
    let d = bn_t_naf[i]
    if d == 1 {
      res = res.mul(self)
    } else if d == -1 {
      res = res.mul(f_inv)
    }
  }
  res
}

///|
/// Encodes `self` as 384 bytes strictly in GB/T 38635 `FE2OS` order:
/// `[c1.c2, c0.c1, c0.c2, c1.c0, c1.c1, c0.c0]` (each 64B `Fp2::to_bytes`).
pub fn Fp12::to_bytes(self : Fp12) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(384, b'\x00')
  self.c1.c2.write_bytes_into(out, 0)
  self.c0.c1.write_bytes_into(out, 64)
  self.c0.c2.write_bytes_into(out, 128)
  self.c1.c0.write_bytes_into(out, 192)
  self.c1.c1.write_bytes_into(out, 256)
  self.c0.c0.write_bytes_into(out, 320)
  Bytes::makei(384, fn(i) { out[i] })
}

///|
/// Strictly decodes 384 bytes in GB/T 38635 `FE2OS` order.
/// Returns `None` if length != 384 or any of the 12 `Fp` coordinates is `>= p`.
pub fn Fp12::from_bytes_strict(b : BytesView) -> Fp12? {
  if b.length() != 384 {
    return None
  }
  let b2 = match Fp2::from_bytes_strict(b[0:64]) {
    Some(x) => x
    None => return None
  }
  let a1 = match Fp2::from_bytes_strict(b[64:128]) {
    Some(x) => x
    None => return None
  }
  let a2 = match Fp2::from_bytes_strict(b[128:192]) {
    Some(x) => x
    None => return None
  }
  let b0 = match Fp2::from_bytes_strict(b[192:256]) {
    Some(x) => x
    None => return None
  }
  let b1 = match Fp2::from_bytes_strict(b[256:320]) {
    Some(x) => x
    None => return None
  }
  let a0 = match Fp2::from_bytes_strict(b[320:384]) {
    Some(x) => x
    None => return None
  }
  Some({ c0: Fp6::new(a0, a1, a2), c1: Fp6::new(b0, b1, b2), })
}
