///|
/// Affine point on BN256 sextic D-type twist `E'(Fp2): y^2 = x^3 + 5u`.
/// Private fields protect the curve and prime-order subgroup `G2` invariants;
/// infinity is canonically `(0, 0, true)`.
#derive(Debug)
pub struct G2Affine {
  priv x : @field.Fp2
  priv y : @field.Fp2
  priv infinity : Bool
}

///|
/// Jacobian projective point `(X, Y, Z)` on `E'(Fp2): y^2 = x^3 + 5u` representing `(X/Z^2, Y/Z^3)`.
/// The point at infinity is represented by `Z == 0`.
#derive(Debug)
pub struct G2Jac {
  priv x : @field.Fp2
  priv y : @field.Fp2
  priv z : @field.Fp2
}

///|
pub impl Eq for G2Affine with fn equal(self, other) {
  self.ct_eq(other)
}

///|
pub impl Eq for G2Jac with fn equal(self, other) {
  self.ct_eq(other)
}

///|
pub fn G2Affine::x(self : G2Affine) -> @field.Fp2 {
  self.x
}

///|
pub fn G2Affine::y(self : G2Affine) -> @field.Fp2 {
  self.y
}

///|
pub fn G2Affine::is_infinity(self : G2Affine) -> Bool {
  self.infinity
}

///|
/// Point at infinity `O` in `G2Affine`.
pub fn G2Affine::identity() -> G2Affine {
  { x: @field.Fp2::zero(), y: @field.Fp2::zero(), infinity: true, }
}

///|
/// Standard BN256 `G2` generator `P2` (GB/T 38635.5-2020), using precomputed Montgomery limbs.
pub fn G2Affine::generator() -> G2Affine {
  let x0 = @field.Fp::from_raw_mont(
    0x260226a68ce2da8fUL, 0x7ee5645edbf6c06bUL, 0xf8f57c82b1495444UL, 0x61fcf018bc47c4d1UL,
  )
  let x1 = @field.Fp::from_raw_mont(
    0xdb6db4822750a8a6UL, 0x84c6135a5121f134UL, 0x1874032f88791d41UL, 0x905112f2b85f3a37UL,
  )
  let y0 = @field.Fp::from_raw_mont(
    0xc03f138f9171c24aUL, 0x92fbab45a15a3ca7UL, 0x2445561e2ff77cdbUL, 0x108495e0c0f62eceUL,
  )
  let y1 = @field.Fp::from_raw_mont(
    0xf7b82dac4c89bfbbUL, 0x3706f3f6a49dc12fUL, 0x1e29de93d3eef769UL, 0x81e448c3c76a5d53UL,
  )
  { x: @field.Fp2::new(x0, x1), y: @field.Fp2::new(y0, y1), infinity: false, }
}

///|
/// Checks whether `self` satisfies `y^2 == x^3 + 5u` on `E'(Fp2)` (infinity is on the curve).
pub fn G2Affine::is_on_curve(self : G2Affine) -> Bool {
  if self.infinity {
    return true
  }
  let lhs = self.y.sqr()
  let rhs = self.x.sqr().mul(self.x).add(@field.Fp2::b_twist())
  lhs.ct_eq(rhs)
}

///|
/// Checks whether `self` lies on `E'(Fp2)` AND in the prime-order `G2` subgroup (`[N]Q == O`).
/// Critical defense against small-subgroup / cofactor attacks since `h2 = 2p - N != 1`.
pub fn G2Affine::is_in_subgroup(self : G2Affine) -> Bool {
  if !self.is_on_curve() {
    return false
  }
  if self.infinity {
    return true
  }
  self.scalar_mul(@field.order_n).is_identity()
}

///|
/// Internal/whitebox helper: constructs an on-curve `E'(Fp2)` point WITHOUT checking `G2` subgroup
/// membership. Used only for adversarial cofactor-attack tests.
fn G2Affine::from_coords_on_curve_unchecked_subgroup(
  x : @field.Fp2,
  y : @field.Fp2,
) -> G2Affine? {
  let pt : G2Affine = { x, y, infinity: false, }
  if pt.is_on_curve() {
    Some(pt)
  } else {
    None
  }
}

///|
/// Strictly constructs a finite `G2Affine` point after verifying BOTH:
/// 1. `y^2 == x^3 + 5u` (`is_on_curve`), and
/// 2. `[N]Q == O` (`is_in_subgroup`).
pub fn G2Affine::from_coords_checked(
  x : @field.Fp2,
  y : @field.Fp2,
) -> G2Affine? {
  match G2Affine::from_coords_on_curve_unchecked_subgroup(x, y) {
    None => None
    Some(pt) => if pt.is_in_subgroup() { Some(pt) } else { None }
  }
}

///|
pub fn G2Affine::neg(self : G2Affine) -> G2Affine {
  { x: self.x, y: self.y.neg(), infinity: self.infinity, }
}

///|
pub fn G2Affine::to_jac(self : G2Affine) -> G2Jac {
  let inf_mask = @field.ct_mask(self.infinity)
  {
    x: @field.Fp2::ct_select(self.x, @field.Fp2::zero(), inf_mask),
    y: @field.Fp2::ct_select(self.y, @field.Fp2::one(), inf_mask),
    z: @field.Fp2::ct_select(@field.Fp2::one(), @field.Fp2::zero(), inf_mask),
  }
}

///|
/// Constant-time selection: returns `a` if `choice == 0UL`, else `b` if `choice == all_ones`.
pub fn G2Affine::ct_select(
  a : G2Affine,
  b : G2Affine,
  choice : UInt64,
) -> G2Affine {
  let a_inf = @field.ct_mask(a.infinity)
  let b_inf = @field.ct_mask(b.infinity)
  let inf = ct_select_u64(a_inf, b_inf, choice) != 0UL
  {
    x: @field.Fp2::ct_select(a.x, b.x, choice),
    y: @field.Fp2::ct_select(a.y, b.y, choice),
    infinity: inf,
  }
}

///|
/// Constant-time equality on `G2Affine`.
pub fn G2Affine::ct_eq(self : G2Affine, other : G2Affine) -> Bool {
  let s_inf = @field.ct_mask(self.infinity)
  let o_inf = @field.ct_mask(other.infinity)
  let both_inf = s_inf & o_inf
  let neither_inf = (s_inf ^ ec_all_ones) & (o_inf ^ ec_all_ones)
  let x_eq = @field.ct_mask(self.x.ct_eq(other.x))
  let y_eq = @field.ct_mask(self.y.ct_eq(other.y))
  (both_inf | (neither_inf & x_eq & y_eq)) != 0UL
}

///|
/// Constant-time scalar multiplication `[k]self` returning Jacobian coordinates.
pub fn G2Affine::scalar_mul(self : G2Affine, k : @field.U256) -> G2Jac {
  self.to_jac().scalar_mul(k)
}

///|
/// Constant-time scalar multiplication `[k]self` for scalar `k` in `Fn`.
pub fn G2Affine::scalar_mul_fn(self : G2Affine, k : @field.Fn) -> G2Jac {
  self.to_jac().scalar_mul_fn(k)
}

///|
/// Raw 128-byte encoding `x1 (32B) || x0 (32B) || y1 (32B) || y0 (32B)` (GB/T 38635).
/// Returns 128 zero bytes if `self` is the point at infinity.
pub fn G2Affine::to_bytes_raw(self : G2Affine) -> Bytes {
  if self.infinity {
    return Bytes::make(128, b'\x00')
  }
  let xb = self.x.to_bytes()
  let yb = self.y.to_bytes()
  Bytes::makei(128, fn(i) { if i < 64 { xb[i] } else { yb[i - 64] } })
}

///|
/// Uncompressed 129-byte encoding `0x04 || x1 || x0 || y1 || y0` (GB/T 38635 / GM/T 0080).
pub fn G2Affine::to_bytes_uncompressed(self : G2Affine) -> Bytes {
  let raw = self.to_bytes_raw()
  Bytes::makei(129, fn(i) { if i == 0 { b'\x04' } else { raw[i - 1] } })
}

///|
/// Strictly decodes 128 raw bytes `x1 || x0 || y1 || y0` into a finite `G2Affine` point.
/// Rejects wrong length, components `>= p`, off-curve points, non-`G2` subgroup points, and infinity.
pub fn G2Affine::from_bytes_raw_strict(b : BytesView) -> G2Affine? {
  if b.length() != 128 {
    return None
  }
  match
    (
      @field.Fp2::from_bytes_strict(b[0:64]),
      @field.Fp2::from_bytes_strict(b[64:128]),
    ) {
    (Some(x), Some(y)) => G2Affine::from_coords_checked(x, y)
    _ => None
  }
}

///|
/// Strictly decodes 129 uncompressed bytes `0x04 || x1 || x0 || y1 || y0` into a finite `G2Affine` point.
/// Rejects wrong length, non-`0x04` prefix, components `>= p`, off-curve points, and non-`G2` points.
pub fn G2Affine::from_bytes_uncompressed_strict(b : BytesView) -> G2Affine? {
  if b.length() != 129 || b[0] != b'\x04' {
    return None
  }
  G2Affine::from_bytes_raw_strict(b[1:129])
}

///|
pub fn G2Jac::x(self : G2Jac) -> @field.Fp2 {
  self.x
}

///|
pub fn G2Jac::y(self : G2Jac) -> @field.Fp2 {
  self.y
}

///|
pub fn G2Jac::z(self : G2Jac) -> @field.Fp2 {
  self.z
}

///|
/// Point at infinity `O` in Jacobian coordinates (`Z == 0`).
pub fn G2Jac::identity() -> G2Jac {
  { x: @field.Fp2::zero(), y: @field.Fp2::one(), z: @field.Fp2::zero(), }
}

///|
/// Standard BN256 `G2` generator `P2` in Jacobian coordinates.
pub fn G2Jac::generator() -> G2Jac {
  G2Affine::generator().to_jac()
}

///|
pub fn G2Jac::is_identity(self : G2Jac) -> Bool {
  self.z.is_zero()
}

///|
/// Constant-time selection: returns `a` if `choice == 0UL`, else `b` if `choice == all_ones`.
pub fn G2Jac::ct_select(a : G2Jac, b : G2Jac, choice : UInt64) -> G2Jac {
  {
    x: @field.Fp2::ct_select(a.x, b.x, choice),
    y: @field.Fp2::ct_select(a.y, b.y, choice),
    z: @field.Fp2::ct_select(a.z, b.z, choice),
  }
}

///|
/// Constant-time projective equality on `G2Jac`.
pub fn G2Jac::ct_eq(self : G2Jac, other : G2Jac) -> Bool {
  let z1_zero = self.z.is_zero_mask()
  let z2_zero = other.z.is_zero_mask()
  let both_inf = z1_zero & z2_zero
  let neither_inf = (z1_zero ^ ec_all_ones) & (z2_zero ^ ec_all_ones)
  let z1z1 = self.z.sqr()
  let z2z2 = other.z.sqr()
  let u1 = self.x.mul(z2z2)
  let u2 = other.x.mul(z1z1)
  let s1 = self.y.mul(other.z).mul(z2z2)
  let s2 = other.y.mul(self.z).mul(z1z1)
  let x_eq = @field.ct_mask(u1.ct_eq(u2))
  let y_eq = @field.ct_mask(s1.ct_eq(s2))
  (both_inf | (neither_inf & x_eq & y_eq)) != 0UL
}

///|
pub fn G2Jac::neg(self : G2Jac) -> G2Jac {
  { x: self.x, y: self.y.neg(), z: self.z, }
}

///|
/// Constant-time conversion from Jacobian to affine coordinates.
pub fn G2Jac::to_affine(self : G2Jac) -> G2Affine {
  let inf_mask = self.z.is_zero_mask()
  let z_inv = self.z.inv()
  let z_inv2 = z_inv.sqr()
  let z_inv3 = z_inv2.mul(z_inv)
  let x = self.x.mul(z_inv2)
  let y = self.y.mul(z_inv3)
  {
    x: @field.Fp2::ct_select(x, @field.Fp2::zero(), inf_mask),
    y: @field.Fp2::ct_select(y, @field.Fp2::zero(), inf_mask),
    infinity: inf_mask != 0UL,
  }
}

///|
/// Constant-time point doubling on `E'(Fp2): y^2 = x^3 + 5u` (`a = 0`, `dbl-2009-l`).
/// Naturally preserves `Z == 0` when `self` is the point at infinity.
pub fn G2Jac::double(self : G2Jac) -> G2Jac {
  let a = self.x.sqr()
  let b = self.y.sqr()
  let c = b.sqr()
  let d = self.x.add(b).sqr().sub(a).sub(c).double()
  let e = a.triple()
  let f = e.sqr()
  let x3 = f.sub(d.double())
  let eight_c = c.double().double().double()
  let y3 = e.mul(d.sub(x3)).sub(eight_c)
  let z3 = self.y.mul(self.z).double()
  { x: x3, y: y3, z: z3, }
}

///|
/// Complete constant-time Jacobian point addition (`add-2007-bl` + branchless `ct_select`).
/// Handles `self == O`, `other == O`, `self == other`, and `self == -other` with zero secret branches.
pub fn G2Jac::add(self : G2Jac, other : G2Jac) -> G2Jac {
  let z1z1 = self.z.sqr()
  let z2z2 = other.z.sqr()
  let u1 = self.x.mul(z2z2)
  let u2 = other.x.mul(z1z1)
  let s1 = self.y.mul(other.z).mul(z2z2)
  let s2 = other.y.mul(self.z).mul(z1z1)
  let h = u2.sub(u1)
  let s_diff = s2.sub(s1)
  let i = h.double().sqr()
  let j = h.mul(i)
  let r = s_diff.double()
  let v = u1.mul(i)
  let x3 = r.sqr().sub(j).sub(v.double())
  let y3 = r.mul(v.sub(x3)).sub(s1.mul(j).double())
  let z3 = self.z.add(other.z).sqr().sub(z1z1).sub(z2z2).mul(h)
  let add_res : G2Jac = { x: x3, y: y3, z: z3, }
  let self_inf = self.z.is_zero_mask()
  let other_inf = other.z.is_zero_mask()
  let h_zero = h.is_zero_mask()
  let r_zero = s_diff.is_zero_mask()
  let is_opposite = h_zero & (r_zero ^ ec_all_ones)
  let is_double = h_zero & r_zero
  let dbl = self.double()
  let res = G2Jac::ct_select(add_res, G2Jac::identity(), is_opposite)
  let res = G2Jac::ct_select(res, dbl, is_double)
  let res = G2Jac::ct_select(res, self, other_inf)
  G2Jac::ct_select(res, other, self_inf)
}

///|
/// Complete constant-time mixed Jacobian + affine point addition (`madd-2007-bl`).
/// Handles `self == O`, `other == O`, `self == other`, and `self == -other` with zero secret branches.
pub fn G2Jac::add_mixed(self : G2Jac, other : G2Affine) -> G2Jac {
  let z1z1 = self.z.sqr()
  let u2 = other.x.mul(z1z1)
  let s2 = other.y.mul(self.z).mul(z1z1)
  let h = u2.sub(self.x)
  let hh = h.sqr()
  let i = hh.double().double()
  let j = h.mul(i)
  let s_diff = s2.sub(self.y)
  let r = s_diff.double()
  let v = self.x.mul(i)
  let x3 = r.sqr().sub(j).sub(v.double())
  let y3 = r.mul(v.sub(x3)).sub(self.y.mul(j).double())
  let z3 = self.z.add(h).sqr().sub(z1z1).sub(hh)
  let add_res : G2Jac = { x: x3, y: y3, z: z3, }
  let self_inf = self.z.is_zero_mask()
  let other_inf = @field.ct_mask(other.infinity)
  let h_zero = h.is_zero_mask()
  let r_zero = s_diff.is_zero_mask()
  let is_opposite = h_zero & (r_zero ^ ec_all_ones)
  let is_double = h_zero & r_zero
  let dbl = self.double()
  let other_jac = other.to_jac()
  let res = G2Jac::ct_select(add_res, G2Jac::identity(), is_opposite)
  let res = G2Jac::ct_select(res, dbl, is_double)
  let res = G2Jac::ct_select(res, self, other_inf)
  G2Jac::ct_select(res, other_jac, self_inf)
}

///|
/// Constant-time subtraction `self - other`.
pub fn G2Jac::sub(self : G2Jac, other : G2Jac) -> G2Jac {
  self.add(other.neg())
}

///|
/// Constant-time 4-bit fixed-window scalar multiplication `[k]self`.
/// Precomputes `[0P, 1P, ..., 15P]` and performs a full linear scan with `ct_select`
/// plus complete constant-time addition for every 4-bit window (no secret branches or indexing).
pub fn G2Jac::scalar_mul(self : G2Jac, k : @field.U256) -> G2Jac {
  let table : FixedArray[G2Jac] = FixedArray::make(16, G2Jac::identity())
  table[1] = self
  for i = 2; i < 16; i = i + 1 {
    table[i] = table[i - 1].add(self)
  }
  let limbs : FixedArray[UInt64] = [k.d3, k.d2, k.d1, k.d0]
  let mut acc = G2Jac::identity()
  for li = 0; li < 4; li = li + 1 {
    let limb = limbs[li]
    for shift = 60; shift >= 0; shift = shift - 4 {
      if li != 0 || shift != 60 {
        acc = acc.double().double().double().double()
      }
      let nib = (limb >> shift) & 0xFUL
      let mut selected = table[0]
      for j = 1; j < 16; j = j + 1 {
        let mask = ct_eq_u64_mask(nib, j.to_uint64())
        selected = G2Jac::ct_select(selected, table[j], mask)
      }
      acc = acc.add(selected)
    }
  }
  acc
}

///|
/// Constant-time scalar multiplication `[k]self` for scalar `k` in `Fn`.
pub fn G2Jac::scalar_mul_fn(self : G2Jac, k : @field.Fn) -> G2Jac {
  self.scalar_mul(k.to_u256())
}
