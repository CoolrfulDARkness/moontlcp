///|
let ec_all_ones : UInt64 = 0xFFFF_FFFF_FFFF_FFFFUL

///|
/// Constant-time 64-bit equality mask: returns `0xFFFF_FFFF_FFFF_FFFFUL` if `a == b`, else `0UL`.
fn ct_eq_u64_mask(a : UInt64, b : UInt64) -> UInt64 {
  let diff = a ^ b
  let nz = (diff | (0UL - diff)) >> 63
  nz - 1UL
}

///|
/// Constant-time 64-bit select: returns `a` if `choice == 0UL`, else `b` if `choice == all_ones`.
fn ct_select_u64(a : UInt64, b : UInt64, choice : UInt64) -> UInt64 {
  a ^ ((a ^ b) & choice)
}

///|
/// Affine point on BN256 base curve `E(Fp): y^2 = x^3 + 5` (`G1`, cofactor `h1 = 1`).
/// Private fields protect the curve invariant; infinity is canonically `(0, 0, true)`.
#derive(Debug)
pub struct G1Affine {
  priv x : @field.Fp
  priv y : @field.Fp
  priv infinity : Bool
}

///|
/// Jacobian projective point `(X, Y, Z)` on `E(Fp): y^2 = x^3 + 5` representing `(X/Z^2, Y/Z^3)`.
/// The point at infinity is represented by `Z == 0`.
#derive(Debug)
pub struct G1Jac {
  priv x : @field.Fp
  priv y : @field.Fp
  priv z : @field.Fp
}

///|
pub impl Eq for G1Affine with fn equal(self, other) {
  self.ct_eq(other)
}

///|
pub impl Eq for G1Jac with fn equal(self, other) {
  self.ct_eq(other)
}

///|
pub fn G1Affine::x(self : G1Affine) -> @field.Fp {
  self.x
}

///|
pub fn G1Affine::y(self : G1Affine) -> @field.Fp {
  self.y
}

///|
pub fn G1Affine::is_infinity(self : G1Affine) -> Bool {
  self.infinity
}

///|
/// Point at infinity `O` in `G1Affine`.
pub fn G1Affine::identity() -> G1Affine {
  { x: @field.Fp::zero(), y: @field.Fp::zero(), infinity: true, }
}

///|
/// Standard BN256 `G1` generator `P1` (GB/T 38635.5-2020), using precomputed Montgomery limbs.
pub fn G1Affine::generator() -> G1Affine {
  {
    x: @field.Fp::from_raw_mont(
      0x22e935e29860501bUL, 0xa946fd5e0073282cUL, 0xefd0cec817a649beUL, 0x5129787c869140b5UL,
    ),
    y: @field.Fp::from_raw_mont(
      0xee779649eb87f7c7UL, 0x15563cbdec30a576UL, 0x326353912824efbfUL, 0x7215717763c39828UL,
    ),
    infinity: false,
  }
}

///|
/// Checks whether `self` satisfies `y^2 == x^3 + 5` (infinity is on the curve).
/// Because `h1 = 1`, every point on `E(Fp)` is automatically in the prime-order subgroup `G1`.
pub fn G1Affine::is_on_curve(self : G1Affine) -> Bool {
  if self.infinity {
    return true
  }
  let lhs = self.y.sqr()
  let rhs = self.x.sqr().mul(self.x).add(@field.Fp::b_const())
  lhs.ct_eq(rhs)
}

///|
/// Constructs a finite `G1Affine` point after verifying `y^2 == x^3 + 5`.
/// Returns `None` if `(x, y)` is not on the curve (which also rejects `(0, 0)`).
pub fn G1Affine::from_coords_checked(x : @field.Fp, y : @field.Fp) -> G1Affine? {
  let pt : G1Affine = { x, y, infinity: false, }
  if pt.is_on_curve() {
    Some(pt)
  } else {
    None
  }
}

///|
pub fn G1Affine::neg(self : G1Affine) -> G1Affine {
  { x: self.x, y: self.y.neg(), infinity: self.infinity, }
}

///|
pub fn G1Affine::to_jac(self : G1Affine) -> G1Jac {
  let inf_mask = @field.ct_mask(self.infinity)
  {
    x: @field.Fp::ct_select(self.x, @field.Fp::zero(), inf_mask),
    y: @field.Fp::ct_select(self.y, @field.Fp::one(), inf_mask),
    z: @field.Fp::ct_select(@field.Fp::one(), @field.Fp::zero(), inf_mask),
  }
}

///|
/// Constant-time selection: returns `a` if `choice == 0UL`, else `b` if `choice == all_ones`.
pub fn G1Affine::ct_select(
  a : G1Affine,
  b : G1Affine,
  choice : UInt64,
) -> G1Affine {
  let a_inf = @field.ct_mask(a.infinity)
  let b_inf = @field.ct_mask(b.infinity)
  let inf = ct_select_u64(a_inf, b_inf, choice) != 0UL
  {
    x: @field.Fp::ct_select(a.x, b.x, choice),
    y: @field.Fp::ct_select(a.y, b.y, choice),
    infinity: inf,
  }
}

///|
/// Constant-time equality on `G1Affine`.
pub fn G1Affine::ct_eq(self : G1Affine, other : G1Affine) -> Bool {
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
pub fn G1Affine::scalar_mul(self : G1Affine, k : @field.U256) -> G1Jac {
  self.to_jac().scalar_mul(k)
}

///|
/// Constant-time scalar multiplication `[k]self` for scalar `k` in `Fn`.
pub fn G1Affine::scalar_mul_fn(self : G1Affine, k : @field.Fn) -> G1Jac {
  self.to_jac().scalar_mul_fn(k)
}

///|
/// Raw 64-byte encoding `x (32B) || y (32B)` (GB/T 38635).
/// Returns 64 zero bytes if `self` is the point at infinity.
pub fn G1Affine::to_bytes_raw(self : G1Affine) -> Bytes {
  if self.infinity {
    return Bytes::make(64, b'\x00')
  }
  let xb = self.x.to_be_bytes()
  let yb = self.y.to_be_bytes()
  Bytes::makei(64, fn(i) { if i < 32 { xb[i] } else { yb[i - 32] } })
}

///|
/// Uncompressed 65-byte encoding `0x04 || x (32B) || y (32B)` (GB/T 38635 / GM/T 0080).
pub fn G1Affine::to_bytes_uncompressed(self : G1Affine) -> Bytes {
  let raw = self.to_bytes_raw()
  Bytes::makei(65, fn(i) { if i == 0 { b'\x04' } else { raw[i - 1] } })
}

///|
/// Compressed 33-byte encoding `0x02/0x03 || x (32B)` (GB/T 38635.1).
/// Returns 33 zero bytes if `self` is the point at infinity.
pub fn G1Affine::to_bytes_compressed(self : G1Affine) -> Bytes {
  if self.infinity {
    return Bytes::make(33, b'\x00')
  }
  let xb = self.x.to_be_bytes()
  let prefix : Byte = if (self.y.to_u256().d0 & 1UL) != 0UL {
    b'\x03'
  } else {
    b'\x02'
  }
  Bytes::makei(33, fn(i) { if i == 0 { prefix } else { xb[i - 1] } })
}

///|
/// Strictly decodes 64 raw bytes `x || y` into a finite `G1Affine` point.
/// Rejects wrong length, coordinates `>= p`, off-curve points, and all-zero/infinity.
pub fn G1Affine::from_bytes_raw_strict(b : BytesView) -> G1Affine? {
  if b.length() != 64 {
    return None
  }
  match
    (
      @field.Fp::from_be_bytes_strict(b[0:32]),
      @field.Fp::from_be_bytes_strict(b[32:64]),
    ) {
    (Some(x), Some(y)) => G1Affine::from_coords_checked(x, y)
    _ => None
  }
}

///|
/// Strictly decodes 65 uncompressed bytes `0x04 || x || y` into a finite `G1Affine` point.
/// Rejects wrong length, non-`0x04` prefix, coordinates `>= p`, and off-curve points.
pub fn G1Affine::from_bytes_uncompressed_strict(b : BytesView) -> G1Affine? {
  if b.length() != 65 || b[0] != b'\x04' {
    return None
  }
  G1Affine::from_bytes_raw_strict(b[1:65])
}

///|
/// Strictly decodes 33 compressed bytes `0x02/0x03 || x` into a finite `G1Affine` point.
/// Rejects wrong length, invalid prefix, `x >= p`, or non-residue `x^3 + 5`.
pub fn G1Affine::from_bytes_compressed_strict(b : BytesView) -> G1Affine? {
  if b.length() != 33 {
    return None
  }
  let want_odd = if b[0] == b'\x02' {
    false
  } else if b[0] == b'\x03' {
    true
  } else {
    return None
  }
  match @field.Fp::from_be_bytes_strict(b[1:33]) {
    None => None
    Some(x) => {
      let rhs = x.sqr().mul(x).add(@field.Fp::b_const())
      match rhs.sqrt() {
        None => None
        Some(y0) => {
          let y0_odd = (y0.to_u256().d0 & 1UL) != 0UL
          let y = if y0_odd == want_odd { y0 } else { y0.neg() }
          let y_odd = (y.to_u256().d0 & 1UL) != 0UL
          if y_odd != want_odd {
            return None
          }
          G1Affine::from_coords_checked(x, y)
        }
      }
    }
  }
}

///|
pub fn G1Jac::x(self : G1Jac) -> @field.Fp {
  self.x
}

///|
pub fn G1Jac::y(self : G1Jac) -> @field.Fp {
  self.y
}

///|
pub fn G1Jac::z(self : G1Jac) -> @field.Fp {
  self.z
}

///|
/// Point at infinity `O` in Jacobian coordinates (`Z == 0`).
pub fn G1Jac::identity() -> G1Jac {
  { x: @field.Fp::zero(), y: @field.Fp::one(), z: @field.Fp::zero(), }
}

///|
/// Standard BN256 `G1` generator `P1` in Jacobian coordinates.
pub fn G1Jac::generator() -> G1Jac {
  G1Affine::generator().to_jac()
}

///|
pub fn G1Jac::is_identity(self : G1Jac) -> Bool {
  self.z.is_zero()
}

///|
/// Constant-time selection: returns `a` if `choice == 0UL`, else `b` if `choice == all_ones`.
pub fn G1Jac::ct_select(a : G1Jac, b : G1Jac, choice : UInt64) -> G1Jac {
  {
    x: @field.Fp::ct_select(a.x, b.x, choice),
    y: @field.Fp::ct_select(a.y, b.y, choice),
    z: @field.Fp::ct_select(a.z, b.z, choice),
  }
}

///|
/// Constant-time projective equality on `G1Jac`.
pub fn G1Jac::ct_eq(self : G1Jac, other : G1Jac) -> Bool {
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
pub fn G1Jac::neg(self : G1Jac) -> G1Jac {
  { x: self.x, y: self.y.neg(), z: self.z, }
}

///|
/// Constant-time conversion from Jacobian to affine coordinates.
pub fn G1Jac::to_affine(self : G1Jac) -> G1Affine {
  let inf_mask = self.z.is_zero_mask()
  let z_inv = self.z.inv()
  let z_inv2 = z_inv.sqr()
  let z_inv3 = z_inv2.mul(z_inv)
  let x = self.x.mul(z_inv2)
  let y = self.y.mul(z_inv3)
  {
    x: @field.Fp::ct_select(x, @field.Fp::zero(), inf_mask),
    y: @field.Fp::ct_select(y, @field.Fp::zero(), inf_mask),
    infinity: inf_mask != 0UL,
  }
}

///|
/// Constant-time point doubling on `E(Fp): y^2 = x^3 + 5` (`a = 0`, `dbl-2009-l`).
/// Naturally preserves `Z == 0` when `self` is the point at infinity.
pub fn G1Jac::double(self : G1Jac) -> G1Jac {
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
pub fn G1Jac::add(self : G1Jac, other : G1Jac) -> G1Jac {
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
  let add_res : G1Jac = { x: x3, y: y3, z: z3, }
  let self_inf = self.z.is_zero_mask()
  let other_inf = other.z.is_zero_mask()
  let h_zero = h.is_zero_mask()
  let r_zero = s_diff.is_zero_mask()
  let is_opposite = h_zero & (r_zero ^ ec_all_ones)
  let is_double = h_zero & r_zero
  let dbl = self.double()
  let res = G1Jac::ct_select(add_res, G1Jac::identity(), is_opposite)
  let res = G1Jac::ct_select(res, dbl, is_double)
  let res = G1Jac::ct_select(res, self, other_inf)
  G1Jac::ct_select(res, other, self_inf)
}

///|
/// Complete constant-time mixed Jacobian + affine point addition (`madd-2007-bl`).
/// Handles `self == O`, `other == O`, `self == other`, and `self == -other` with zero secret branches.
pub fn G1Jac::add_mixed(self : G1Jac, other : G1Affine) -> G1Jac {
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
  let add_res : G1Jac = { x: x3, y: y3, z: z3, }
  let self_inf = self.z.is_zero_mask()
  let other_inf = @field.ct_mask(other.infinity)
  let h_zero = h.is_zero_mask()
  let r_zero = s_diff.is_zero_mask()
  let is_opposite = h_zero & (r_zero ^ ec_all_ones)
  let is_double = h_zero & r_zero
  let dbl = self.double()
  let other_jac = other.to_jac()
  let res = G1Jac::ct_select(add_res, G1Jac::identity(), is_opposite)
  let res = G1Jac::ct_select(res, dbl, is_double)
  let res = G1Jac::ct_select(res, self, other_inf)
  G1Jac::ct_select(res, other_jac, self_inf)
}

///|
/// Constant-time subtraction `self - other`.
pub fn G1Jac::sub(self : G1Jac, other : G1Jac) -> G1Jac {
  self.add(other.neg())
}

///|
/// Constant-time 4-bit fixed-window scalar multiplication `[k]self`.
/// Precomputes `[0P, 1P, ..., 15P]` and performs a full linear scan with `ct_select`
/// plus complete constant-time addition for every 4-bit window (no secret branches or indexing).
pub fn G1Jac::scalar_mul(self : G1Jac, k : @field.U256) -> G1Jac {
  let table : FixedArray[G1Jac] = FixedArray::make(16, G1Jac::identity())
  table[1] = self
  for i = 2; i < 16; i = i + 1 {
    table[i] = table[i - 1].add(self)
  }
  let limbs : FixedArray[UInt64] = [k.d3, k.d2, k.d1, k.d0]
  let mut acc = G1Jac::identity()
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
        selected = G1Jac::ct_select(selected, table[j], mask)
      }
      acc = acc.add(selected)
    }
  }
  acc
}

///|
/// Constant-time scalar multiplication `[k]self` for scalar `k` in `Fn`.
pub fn G1Jac::scalar_mul_fn(self : G1Jac, k : @field.Fn) -> G1Jac {
  self.scalar_mul(k.to_u256())
}
