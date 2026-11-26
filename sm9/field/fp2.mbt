///|
/// Quadratic extension field `Fp2 = Fp[u] / (u^2 + 2)` representing `c0 + c1 * u`.
#derive(Eq, Debug)
pub struct Fp2 {
  c0 : Fp
  c1 : Fp
}

///|
pub fn Fp2::new(c0 : Fp, c1 : Fp) -> Fp2 {
  { c0, c1, }
}

///|
pub fn Fp2::zero() -> Fp2 {
  { c0: Fp::zero(), c1: Fp::zero(), }
}

///|
pub fn Fp2::one() -> Fp2 {
  { c0: Fp::one(), c1: Fp::zero(), }
}

///|
pub fn Fp2::from_fp(c0 : Fp) -> Fp2 {
  { c0, c1: Fp::zero(), }
}

///|
/// Returns the D-type sextic twist curve constant `b' = 5u = (0, 5)` (GB/T 38635.5).
pub fn Fp2::b_twist() -> Fp2 {
  { c0: Fp::zero(), c1: Fp::b_const(), }
}

///|
/// Constant-time zero mask: returns `0xFFFF_FFFF_FFFF_FFFFUL` if `self == 0`, else `0UL`.
/// Implemented purely via bitwise operations without converting through `Bool` or `if`.
pub fn Fp2::is_zero_mask(self : Fp2) -> UInt64 {
  self.c0.is_zero_mask() & self.c1.is_zero_mask()
}

///|
pub fn Fp2::is_zero(self : Fp2) -> Bool {
  self.is_zero_mask() != 0UL
}

///|
pub fn Fp2::is_one(self : Fp2) -> Bool {
  self.c0.is_one() && self.c1.is_zero()
}

///|
pub fn Fp2::ct_eq(self : Fp2, other : Fp2) -> Bool {
  let m0 = ct_mask(self.c0.ct_eq(other.c0))
  let m1 = ct_mask(self.c1.ct_eq(other.c1))
  (m0 & m1) != 0UL
}

///|
pub fn Fp2::ct_select(a : Fp2, b : Fp2, choice : UInt64) -> Fp2 {
  {
    c0: Fp::ct_select(a.c0, b.c0, choice),
    c1: Fp::ct_select(a.c1, b.c1, choice),
  }
}

///|
pub fn Fp2::add(self : Fp2, other : Fp2) -> Fp2 {
  { c0: self.c0.add(other.c0), c1: self.c1.add(other.c1), }
}

///|
pub fn Fp2::sub(self : Fp2, other : Fp2) -> Fp2 {
  { c0: self.c0.sub(other.c0), c1: self.c1.sub(other.c1), }
}

///|
pub fn Fp2::neg(self : Fp2) -> Fp2 {
  { c0: self.c0.neg(), c1: self.c1.neg(), }
}

///|
pub fn Fp2::double(self : Fp2) -> Fp2 {
  { c0: self.c0.double(), c1: self.c1.double(), }
}

///|
pub fn Fp2::triple(self : Fp2) -> Fp2 {
  { c0: self.c0.triple(), c1: self.c1.triple(), }
}

///|
/// Karatsuba multiplication in `Fp2` with `u^2 = -2`.
pub fn Fp2::mul(self : Fp2, other : Fp2) -> Fp2 {
  let v0 = self.c0.mul(other.c0)
  let v1 = self.c1.mul(other.c1)
  let c0 = v0.sub(v1.double())
  let c1 = self.c0.add(self.c1).mul(other.c0.add(other.c1)).sub(v0).sub(v1)
  { c0, c1, }
}

///|
/// Squaring in `Fp2` using 2 `Fp` multiplications (`u^2 = -2`).
pub fn Fp2::sqr(self : Fp2) -> Fp2 {
  let ab = self.c0.mul(self.c1)
  let c0 = self.c0.add(self.c1).mul(self.c0.sub(self.c1.double())).add(ab)
  let c1 = ab.double()
  { c0, c1, }
}

///|
pub fn Fp2::mul_fp(self : Fp2, k : Fp) -> Fp2 {
  { c0: self.c0.mul(k), c1: self.c1.mul(k), }
}

///|
/// Multiplies by `u`: `(c0 + c1*u)*u = -2*c1 + c0*u`.
pub fn Fp2::mul_by_u(self : Fp2) -> Fp2 {
  { c0: self.c1.double().neg(), c1: self.c0, }
}

///|
/// Multiplies by `5u`: `(c0 + c1*u)*(5u) = -10*c1 + 5*c0*u`.
pub fn Fp2::mul_by_5u(self : Fp2) -> Fp2 {
  { c0: self.c1.mul_by_5().double().neg(), c1: self.c0.mul_by_5(), }
}

///|
/// Frobenius conjugation `self^p = c0 - c1 * u`.
pub fn Fp2::conjugate(self : Fp2) -> Fp2 {
  { c0: self.c0, c1: self.c1.neg(), }
}

///|
/// Constant-time inversion in `Fp2`. Returns `0` for `self == 0`.
pub fn Fp2::inv(self : Fp2) -> Fp2 {
  let norm = self.c0.sqr().add(self.c1.sqr().double())
  let t = norm.inv()
  { c0: self.c0.mul(t), c1: self.c1.neg().mul(t), }
}

///|
/// Checked inversion returning `None` when `self == 0`.
pub fn Fp2::inv_checked(self : Fp2) -> Fp2? {
  if self.is_zero() {
    None
  } else {
    Some(self.inv())
  }
}

///|
fn Fp2::write_bytes_into(
  self : Fp2,
  out : FixedArray[Byte],
  off : Int32,
) -> Unit {
  // GB/T 38635 FE2OS order: c1 (u-coefficient) || c0 (constant term)
  self.c1.write_be_bytes_into(out, off)
  self.c0.write_be_bytes_into(out, off + 32)
}

///|
/// Encodes `self` as 64 bytes strictly in GB/T 38635 `FE2OS` order: `c1 (32B) || c0 (32B)`.
pub fn Fp2::to_bytes(self : Fp2) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(64, b'\x00')
  self.write_bytes_into(out, 0)
  Bytes::makei(64, fn(i) { out[i] })
}

///|
/// Strictly decodes 64 bytes in GB/T 38635 `FE2OS` order (`c1 || c0`).
/// Returns `None` if length != 64 or either component is `>= p`.
pub fn Fp2::from_bytes_strict(b : BytesView) -> Fp2? {
  if b.length() != 64 {
    return None
  }
  match
    (Fp::from_be_bytes_strict(b[0:32]), Fp::from_be_bytes_strict(b[32:64])) {
    (Some(c1), Some(c0)) => Some({ c0, c1, })
    _ => None
  }
}
