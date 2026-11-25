///|
/// GB/T 32918-2016 SM2 elliptic curve (sm2p256v1) point arithmetic in
/// Jacobian projective coordinates with constant-time 4-bit windowed scalar
/// multiplication and Shamir's trick for verification.

///|
/// SM2 curve parameter a = p - 3
let sm2_a : FixedArray[UInt32] = [
  0xFFFFFFFCU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
  0xFFFFFFFEU,
]

///|
/// SM2 curve parameter b
let sm2_b : FixedArray[UInt32] = [
  0x4D940E93U, 0xDDBCBD41U, 0x15AB8F92U, 0xF39789F5U, 0xCF6509A7U, 0x4D5A9E4BU, 0x9D9F5E34U,
  0x28E9FA9EU,
]

///|
/// SM2 base point G x-coordinate
let sm2_gx : FixedArray[UInt32] = [
  0x334C74C7U, 0x715A4589U, 0xF2660BE1U, 0x8FE30BBFU, 0x6A39C994U, 0x5F990446U, 0x1F198119U,
  0x32C4AE2CU,
]

///|
/// SM2 base point G y-coordinate
let sm2_gy : FixedArray[UInt32] = [
  0x2139F0A0U, 0x02DF32E5U, 0xC62A4740U, 0xD0A9877CU, 0x6B692153U, 0x59BDCEE3U, 0xF4F6779CU,
  0xBC3736A2U,
]

///|
priv struct AffinePoint {
  x : U256
  y : U256
  is_inf : Bool
}

///|
priv struct JacPoint {
  x : U256
  y : U256
  z : U256
  is_inf : UInt32 // 1U if point at infinity, 0U otherwise
}

///|
fn sm2_generator() -> AffinePoint {
  { x: u256_from_limbs(sm2_gx), y: u256_from_limbs(sm2_gy), is_inf: false, }
}

///|
fn jac_inf() -> JacPoint {
  { x: u256_zero(), y: u256_one(), z: u256_zero(), is_inf: 1U, }
}

///|
fn jac_from_affine(p : AffinePoint) -> JacPoint {
  if p.is_inf {
    jac_inf()
  } else {
    { x: u256_clone(p.x), y: u256_clone(p.y), z: u256_one(), is_inf: 0U, }
  }
}

///|
fn jac_ct_select(cond : UInt32, a : JacPoint, b : JacPoint) -> JacPoint {
  {
    x: u256_ct_select(cond, a.x, b.x),
    y: u256_ct_select(cond, a.y, b.y),
    z: u256_ct_select(cond, a.z, b.z),
    is_inf: @ct.ct_select_u32(cond, a.is_inf, b.is_inf),
  }
}

///|
/// Checks whether an affine point (x, y) satisfies y^2 === x^3 + a*x + b (mod p)
/// with 0 <= x, y < p.
fn point_is_on_curve(x : U256, y : U256) -> Bool {
  if !fe_is_canonical(x) || !fe_is_canonical(y) {
    return false
  }
  let y2 = fe_sqr(y)
  let x2 = fe_sqr(x)
  let x3 = fe_mul(x2, x)
  let ax = fe_mul(u256_from_limbs(sm2_a), x)
  let rhs = fe_add(fe_add(x3, ax), u256_from_limbs(sm2_b))
  u256_eq(y2, rhs)
}

///|
/// Decompresses an x-coordinate with desired y-parity (`want_odd`) into a valid affine point.
fn point_decompress(x : U256, want_odd : Bool) -> AffinePoint? {
  if !fe_is_canonical(x) {
    return None
  }
  let x2 = fe_sqr(x)
  let x3 = fe_mul(x2, x)
  let ax = fe_mul(u256_from_limbs(sm2_a), x)
  let rhs = fe_add(fe_add(x3, ax), u256_from_limbs(sm2_b))
  let mut y = fe_sqrt(rhs)
  if !u256_eq(fe_sqr(y), rhs) {
    return None
  }
  let y_is_odd = (y.limbs[0] & 1U) == 1U
  if y_is_odd != want_odd {
    y = fe_neg(y)
  }
  // Re-verify parity (guards against y == 0 with want_odd == true)
  if ((y.limbs[0] & 1U) == 1U) != want_odd {
    return None
  }
  Some({ x, y, is_inf: false, })
}

///|
/// Converts a Jacobian point to affine coordinates.
fn jac_to_affine(p : JacPoint) -> AffinePoint {
  if p.is_inf != 0U || u256_is_zero(p.z) {
    return { x: u256_zero(), y: u256_zero(), is_inf: true, }
  }
  let z_inv = fe_inv(p.z)
  let z_inv2 = fe_sqr(z_inv)
  let z_inv3 = fe_mul(z_inv2, z_inv)
  let x = fe_mul(p.x, z_inv2)
  let y = fe_mul(p.y, z_inv3)
  { x, y, is_inf: false, }
}

///|
/// Jacobian point doubling optimized for a = -3 (mod p): 3M + 5S.
fn jac_double(p : JacPoint) -> JacPoint {
  if p.is_inf != 0U || u256_is_zero(p.y) {
    return jac_inf()
  }
  let delta = fe_sqr(p.z)
  let gamma = fe_sqr(p.y)
  let beta = fe_mul(p.x, gamma)
  let alpha_t = fe_mul(fe_sub(p.x, delta), fe_add(p.x, delta))
  let alpha = fe_add(fe_double(alpha_t), alpha_t) // 3 * (X - Z^2) * (X + Z^2)
  let beta4 = fe_double(fe_double(beta))
  let beta8 = fe_double(beta4)
  let x3 = fe_sub(fe_sqr(alpha), beta8)
  let z3 = fe_sub(fe_sub(fe_sqr(fe_add(p.y, p.z)), gamma), delta)
  let gamma2 = fe_sqr(gamma)
  let gamma2_8 = fe_double(fe_double(fe_double(gamma2)))
  let y3 = fe_sub(fe_mul(alpha, fe_sub(beta4, x3)), gamma2_8)
  { x: x3, y: y3, z: z3, is_inf: 0U, }
}

///|
/// Complete Jacobian point addition handling infinity, point doubling, and point inverses.
fn jac_add(p : JacPoint, q : JacPoint) -> JacPoint {
  let z1_sq = fe_sqr(p.z)
  let z2_sq = fe_sqr(q.z)
  let u1 = fe_mul(p.x, z2_sq)
  let u2 = fe_mul(q.x, z1_sq)
  let s1 = fe_mul(p.y, fe_mul(z2_sq, q.z))
  let s2 = fe_mul(q.y, fe_mul(z1_sq, p.z))
  let h = fe_sub(u2, u1)
  let r = fe_sub(s2, s1)

  let h_zero = if u256_is_zero(h) { 1U } else { 0U }
  let r_zero = if u256_is_zero(r) { 1U } else { 0U }

  let h2 = fe_sqr(h)
  let h3 = fe_mul(h2, h)
  let u1_h2 = fe_mul(u1, h2)
  let x3 = fe_sub(fe_sub(fe_sqr(r), h3), fe_double(u1_h2))
  let y3 = fe_sub(fe_mul(r, fe_sub(u1_h2, x3)), fe_mul(s1, h3))
  let z3 = fe_mul(fe_mul(p.z, q.z), h)
  let general : JacPoint = { x: x3, y: y3, z: z3, is_inf: 0U, }

  // Select degenerate cases in constant time
  let mut res = general
  // If h == 0 and r != 0 -> P + (-P) = O
  let is_inv = h_zero & (1U - r_zero)
  res = jac_ct_select(is_inv, jac_inf(), res)
  // If h == 0 and r == 0 -> P + P = 2P (compute lazily only when needed or unconditionally)
  let is_dbl = h_zero & r_zero & (1U - p.is_inf) & (1U - q.is_inf)
  let doubled = jac_double(p)
  res = jac_ct_select(is_dbl, doubled, res)
  // If P is inf -> Q; if Q is inf -> P
  res = jac_ct_select(p.is_inf, q, res)
  res = jac_ct_select(q.is_inf, p, res)
  res
}

///|
/// Constant-time 4-bit fixed-window scalar multiplication `k * P`.
fn scalar_mul(k : U256, p : AffinePoint) -> AffinePoint {
  if p.is_inf || u256_is_zero(k) {
    return { x: u256_zero(), y: u256_zero(), is_inf: true, }
  }
  // Precompute table[i] = i * P for i in 0..15
  let table : FixedArray[JacPoint] = FixedArray::make(16, jac_inf())
  let p_jac = jac_from_affine(p)
  table[1] = p_jac
  for i = 2; i < 16; i = i + 1 {
    if (i & 1) == 0 {
      table[i] = jac_double(table[i >> 1])
    } else {
      table[i] = jac_add(table[i - 1], p_jac)
    }
  }

  let mut acc = jac_inf()
  for nib = 63; nib >= 0; nib = nib - 1 {
    if nib < 63 {
      acc = jac_double(acc)
      acc = jac_double(acc)
      acc = jac_double(acc)
      acc = jac_double(acc)
    }
    let idx = u256_get_nibble(k, nib)
    // Constant-time table lookup over all 16 entries
    let mut selected = jac_inf()
    for j = 0; j < 16; j = j + 1 {
      let eq = @ct.ct_eq_u32(idx, j.reinterpret_as_uint())
      selected = jac_ct_select(eq, table[j], selected)
    }
    acc = jac_add(acc, selected)
  }
  jac_to_affine(acc)
}

///|
/// Scalar multiplication of base point G: `k * G`.
fn scalar_mul_base(k : U256) -> AffinePoint {
  scalar_mul(k, sm2_generator())
}

///|
/// Joint multi-scalar multiplication `s * G + t * P` via Shamir's trick (public verification).
fn scalar_mul_add_base(s : U256, t : U256, p : AffinePoint) -> AffinePoint {
  let g_jac = jac_from_affine(sm2_generator())
  let p_jac = jac_from_affine(p)
  let gp_jac = jac_add(g_jac, p_jac)
  let mut acc = jac_inf()
  for bit = 255; bit >= 0; bit = bit - 1 {
    if acc.is_inf == 0U {
      acc = jac_double(acc)
    }
    let sb = u256_get_bit(s, bit)
    let tb = u256_get_bit(t, bit)
    if sb == 1U && tb == 1U {
      acc = jac_add(acc, gp_jac)
    } else if sb == 1U {
      acc = jac_add(acc, g_jac)
    } else if tb == 1U {
      acc = jac_add(acc, p_jac)
    }
  }
  jac_to_affine(acc)
}
