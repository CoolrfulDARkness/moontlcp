///|
/// Sextic extension field `Fp6 = Fp2[s] / (s^3 - u)` representing `c0 + c1*s + c2*s^2`.
#derive(Eq, Debug)
pub struct Fp6 {
  c0 : Fp2
  c1 : Fp2
  c2 : Fp2
}

///|
pub fn Fp6::new(c0 : Fp2, c1 : Fp2, c2 : Fp2) -> Fp6 {
  { c0, c1, c2, }
}

///|
pub fn Fp6::zero() -> Fp6 {
  { c0: Fp2::zero(), c1: Fp2::zero(), c2: Fp2::zero(), }
}

///|
pub fn Fp6::one() -> Fp6 {
  { c0: Fp2::one(), c1: Fp2::zero(), c2: Fp2::zero(), }
}

///|
pub fn Fp6::from_fp2(c0 : Fp2) -> Fp6 {
  { c0, c1: Fp2::zero(), c2: Fp2::zero(), }
}

///|
pub fn Fp6::is_zero(self : Fp6) -> Bool {
  self.c0.is_zero() && self.c1.is_zero() && self.c2.is_zero()
}

///|
pub fn Fp6::is_one(self : Fp6) -> Bool {
  self.c0.is_one() && self.c1.is_zero() && self.c2.is_zero()
}

///|
pub fn Fp6::ct_eq(self : Fp6, other : Fp6) -> Bool {
  let m0 = ct_mask(self.c0.ct_eq(other.c0))
  let m1 = ct_mask(self.c1.ct_eq(other.c1))
  let m2 = ct_mask(self.c2.ct_eq(other.c2))
  (m0 & m1 & m2) != 0UL
}

///|
pub fn Fp6::ct_select(a : Fp6, b : Fp6, choice : UInt64) -> Fp6 {
  {
    c0: Fp2::ct_select(a.c0, b.c0, choice),
    c1: Fp2::ct_select(a.c1, b.c1, choice),
    c2: Fp2::ct_select(a.c2, b.c2, choice),
  }
}

///|
pub fn Fp6::add(self : Fp6, other : Fp6) -> Fp6 {
  {
    c0: self.c0.add(other.c0),
    c1: self.c1.add(other.c1),
    c2: self.c2.add(other.c2),
  }
}

///|
pub fn Fp6::sub(self : Fp6, other : Fp6) -> Fp6 {
  {
    c0: self.c0.sub(other.c0),
    c1: self.c1.sub(other.c1),
    c2: self.c2.sub(other.c2),
  }
}

///|
pub fn Fp6::neg(self : Fp6) -> Fp6 {
  { c0: self.c0.neg(), c1: self.c1.neg(), c2: self.c2.neg(), }
}

///|
pub fn Fp6::double(self : Fp6) -> Fp6 {
  { c0: self.c0.double(), c1: self.c1.double(), c2: self.c2.double(), }
}

///|
pub fn Fp6::mul_fp(self : Fp6, k : Fp) -> Fp6 {
  { c0: self.c0.mul_fp(k), c1: self.c1.mul_fp(k), c2: self.c2.mul_fp(k), }
}

///|
/// Karatsuba multiplication in `Fp6` with `s^3 = u`.
pub fn Fp6::mul(self : Fp6, other : Fp6) -> Fp6 {
  let v0 = self.c0.mul(other.c0)
  let v1 = self.c1.mul(other.c1)
  let v2 = self.c2.mul(other.c2)
  let c0 = self.c1
    .add(self.c2)
    .mul(other.c1.add(other.c2))
    .sub(v1)
    .sub(v2)
    .mul_by_u()
    .add(v0)
  let c1 = self.c0
    .add(self.c1)
    .mul(other.c0.add(other.c1))
    .sub(v0)
    .sub(v1)
    .add(v2.mul_by_u())
  let c2 = self.c0
    .add(self.c2)
    .mul(other.c0.add(other.c2))
    .sub(v0)
    .sub(v2)
    .add(v1)
  { c0, c1, c2, }
}

///|
/// Chung-Hasan SQR2 squaring in `Fp6`.
pub fn Fp6::sqr(self : Fp6) -> Fp6 {
  let s0 = self.c0.sqr()
  let s1 = self.c0.mul(self.c1).double()
  let s2 = self.c0.sub(self.c1).add(self.c2).sqr()
  let s3 = self.c1.mul(self.c2).double()
  let s4 = self.c2.sqr()
  let c0 = s0.add(s3.mul_by_u())
  let c1 = s1.add(s4.mul_by_u())
  let c2 = s1.add(s2).add(s3).sub(s0).sub(s4)
  { c0, c1, c2, }
}

///|
/// Multiplies by `s`: `(c0 + c1*s + c2*s^2)*s = c2*u + c0*s + c1*s^2`.
pub fn Fp6::mul_by_s(self : Fp6) -> Fp6 {
  { c0: self.c2.mul_by_u(), c1: self.c0, c2: self.c1, }
}

///|
/// Sparse multiplication by `b0 + b1*s`.
pub fn Fp6::mul_by_01(self : Fp6, b0 : Fp2, b1 : Fp2) -> Fp6 {
  let aa = self.c0.mul(b0)
  let bb = self.c1.mul(b1)
  let c0 = self.c2.mul(b1).mul_by_u().add(aa)
  let c1 = self.c0.add(self.c1).mul(b0.add(b1)).sub(aa).sub(bb)
  let c2 = self.c2.mul(b0).add(bb)
  { c0, c1, c2, }
}

///|
/// Sparse multiplication by `b1*s`.
pub fn Fp6::mul_by_1(self : Fp6, b1 : Fp2) -> Fp6 {
  { c0: self.c2.mul(b1).mul_by_u(), c1: self.c0.mul(b1), c2: self.c1.mul(b1), }
}

///|
/// Constant-time inversion in `Fp6`. Returns `0` for `self == 0`.
pub fn Fp6::inv(self : Fp6) -> Fp6 {
  let t0 = self.c0.sqr().sub(self.c1.mul(self.c2).mul_by_u())
  let t1 = self.c2.sqr().mul_by_u().sub(self.c0.mul(self.c1))
  let t2 = self.c1.sqr().sub(self.c0.mul(self.c2))
  let norm = self.c0
    .mul(t0)
    .add(self.c2.mul(t1).add(self.c1.mul(t2)).mul_by_u())
  let inv_norm = norm.inv()
  { c0: t0.mul(inv_norm), c1: t1.mul(inv_norm), c2: t2.mul(inv_norm), }
}

///|
/// Checked inversion returning `None` when `self == 0`.
pub fn Fp6::inv_checked(self : Fp6) -> Fp6? {
  if self.is_zero() {
    None
  } else {
    Some(self.inv())
  }
}

///|
/// Frobenius endomorphism `self^p` in `Fp6`.
pub fn Fp6::frobenius_p(self : Fp6) -> Fp6 {
  {
    c0: self.c0.conjugate(),
    c1: self.c1.conjugate().mul_fp(gamma_12()),
    c2: self.c2.conjugate().mul_fp(gamma_14()),
  }
}

///|
/// Frobenius endomorphism `self^{p^2}` in `Fp6`.
pub fn Fp6::frobenius_p2(self : Fp6) -> Fp6 {
  {
    c0: self.c0,
    c1: self.c1.mul_fp(gamma_22()),
    c2: self.c2.mul_fp(gamma_24()),
  }
}
