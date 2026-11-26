///|
/// NAF representation of `6*BN_T + 2 = 0x02400000000215d93e` (LSB to MSB, 66 entries, 11 non-zero).
let six_t_plus_2_naf : FixedArray[Int32] = [
  0, -1, 0, 0, 0, 0, 1, 0, 1, 0, 0, -1, 0, -1, 0, 0, 0, -1, 0, -1, 0, 1, 0, 0, 0,
  1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1,
]

///|
/// Internal Jacobian point on the D-type sextic twist `E'(Fp2): y^2 = x^3 + 5u`.
priv struct TwistJac {
  x : @field.Fp2
  y : @field.Fp2
  z : @field.Fp2
}

///|
fn TwistJac::from_affine(x : @field.Fp2, y : @field.Fp2) -> TwistJac {
  { x, y, z: @field.Fp2::one(), }
}

///|
/// Zero-inversion Jacobian point doubling and tangent line evaluation on `E'(Fp2): y^2 = x^3 + 5u`.
///
/// For `T = (X1, Y1, Z1)` representing `(X1/Z1^2, Y1/Z1^3)`, computes `2T = (X3, Y3, Z3)` and
/// returns sparse `Fp12` line coefficients `(a, b, c)` corresponding to
/// `l(P) = (a + b*s) + (c*s)*t = (2*Y1*Z1^3) * ((lambda*xT - yT) + (-lambda*xP)*s + yP*s*t)`.
/// The common factor `2*Y1*Z1^3 in Fp2*` is annihilated by the easy part `p^6 - 1` of final_exponentiation.
fn line_double(
  t : TwistJac,
  neg_px : @field.Fp,
  py : @field.Fp,
) -> (TwistJac, @field.Fp2, @field.Fp2, @field.Fp2) {
  let z1_sq = t.z.sqr()
  let t0 = t.x.sqr()
  let t1 = t.y.sqr()
  let t2 = t1.sqr()
  // M = 3 * X1^2
  let m = t0.triple()
  // S = 4 * X1 * Y1^2 = 2 * ((X1 + Y1^2)^2 - X1^2 - Y1^4)
  let s = t.x.add(t1).sqr().sub(t0).sub(t2).double()
  // X3 = M^2 - 2*S
  let x3 = m.sqr().sub(s.double())
  // Y3 = M * (S - X3) - 8 * Y1^4
  let y3 = m.mul(s.sub(x3)).sub(t2.double().double().double())
  // Z3 = 2 * Y1 * Z1
  let z3 = t.y.mul(t.z).double()
  // Line coefficients scaled by kappa = Z3 * Z1^2 = 2 * Y1 * Z1^3 in Fp2:
  //   a = 3 * X1^3 - 2 * Y1^2
  //   b = -(3 * X1^2 * Z1^2) * xP
  //   c = (Z3 * Z1^2) * yP
  let a = m.mul(t.x).sub(t1.double())
  let b = m.mul(z1_sq).mul_fp(neg_px)
  let c = z3.mul(z1_sq).mul_fp(py)
  ({ x: x3, y: y3, z: z3, }, a, b, c)
}

///|
/// Zero-inversion Jacobian mixed addition and chord line evaluation on `E'(Fp2)`.
///
/// Adds affine `R = (rx, ry)` to Jacobian `T = (X1, Y1, Z1)` and returns `T + R` together with
/// sparse `Fp12` line coefficients `(a, b, c)` scaled by `Z3 = H * Z1 in Fp2*`.
fn line_add(
  t : TwistJac,
  rx : @field.Fp2,
  ry : @field.Fp2,
  neg_px : @field.Fp,
  py : @field.Fp,
) -> (TwistJac, @field.Fp2, @field.Fp2, @field.Fp2) {
  let z1_sq = t.z.sqr()
  let z1_cu = z1_sq.mul(t.z)
  let u2 = rx.mul(z1_sq)
  let s2 = ry.mul(z1_cu)
  let h = u2.sub(t.x)
  let r = s2.sub(t.y)
  let z3 = h.mul(t.z)
  let h_sq = h.sqr()
  let h_cu = h_sq.mul(h)
  let v = t.x.mul(h_sq)
  let x3 = r.sqr().sub(h_cu).sub(v.double())
  let y3 = r.mul(v.sub(x3)).sub(t.y.mul(h_cu))
  // Line through T and R = (rx, ry), scaled by kappa = Z3 = H * Z1 in Fp2:
  //   a = r * rx - ry * Z3
  //   b = -r * xP
  //   c = Z3 * yP
  let a = r.mul(rx).sub(ry.mul(z3))
  let b = r.mul_fp(neg_px)
  let c = z3.mul_fp(py)
  ({ x: x3, y: y3, z: z3, }, a, b, c)
}

///|
/// Zero-inversion chord line evaluation for the final Miller step where the updated point `T + R`
/// is no longer needed.
fn line_add_eval_only(
  t : TwistJac,
  rx : @field.Fp2,
  ry : @field.Fp2,
  neg_px : @field.Fp,
  py : @field.Fp,
) -> (@field.Fp2, @field.Fp2, @field.Fp2) {
  let z1_sq = t.z.sqr()
  let z1_cu = z1_sq.mul(t.z)
  let u2 = rx.mul(z1_sq)
  let s2 = ry.mul(z1_cu)
  let h = u2.sub(t.x)
  let r = s2.sub(t.y)
  let z3 = h.mul(t.z)
  let a = r.mul(rx).sub(ry.mul(z3))
  let b = r.mul_fp(neg_px)
  let c = z3.mul_fp(py)
  (a, b, c)
}

///|
/// Builds a sparse `Fp12` element `(a + b*s) + (c*s)*t` directly (used on the first Miller step).
fn sparse_line_fp12(
  a : @field.Fp2,
  b : @field.Fp2,
  c : @field.Fp2,
) -> @field.Fp12 {
  @field.Fp12::new(
    @field.Fp6::new(a, b, @field.Fp2::zero()),
    @field.Fp6::new(@field.Fp2::zero(), c, @field.Fp2::zero()),
  )
}

///|
/// Computes the twist Frobenius images `Q1 = pi_p(Q)` and `-Q2 = -pi_{p^2}(Q)` on `E'(Fp2)`.
///
/// Since `TWIST_FROB_Y2 = -1 mod p`, `(-qy) * TWIST_FROB_Y2 = qy`.
fn twist_frobenius_points(
  qx : @field.Fp2,
  qy : @field.Fp2,
) -> (@field.Fp2, @field.Fp2, @field.Fp2, @field.Fp2) {
  let q1x = qx.conjugate().mul_fp(@field.twist_frob_x1())
  let q1y = qy.conjugate().mul_fp(@field.twist_frob_y1())
  let neg_q2x = qx.mul_fp(@field.twist_frob_x2())
  let neg_q2y = qy
  (q1x, q1y, neg_q2x, neg_q2y)
}

///|
/// Returns true if the affine coordinate pair represents the `(0, 0)` infinity sentinel.
fn is_g1_zero(px : @field.Fp, py : @field.Fp) -> Bool {
  px.is_zero() && py.is_zero()
}

///|
/// Returns true if the affine twist coordinate pair represents the `(0, 0)` infinity sentinel.
fn is_g2_zero(qx : @field.Fp2, qy : @field.Fp2) -> Bool {
  qx.is_zero() && qy.is_zero()
}

///|
/// Computes the BN256 optimal R-ate Miller loop for `Q = (qx, qy) in G2` and `P = (px, py) in G1`
/// using zero-inversion Jacobian line functions and the 66-bit `6t + 2` NAF.
///
/// # Security Preconditions
/// Callers MUST ensure the input coordinates represent valid prime-order subgroup points
/// `Q in G2 \ {O}` (on `E'(Fp2)` with `[N]Q == O`) and `P in G1 \ {O}` (on `E(Fp)`),
/// or the explicit `(0, 0)` infinity sentinel. High-level callers should prefer typed
/// `@kgc.pair` or `@moonsm9.pair` with validated `G2Affine` / `G1Affine` points.
pub fn miller_loop(
  qx : @field.Fp2,
  qy : @field.Fp2,
  px : @field.Fp,
  py : @field.Fp,
) -> @field.Fp12 {
  if is_g2_zero(qx, qy) || is_g1_zero(px, py) {
    return @field.Fp12::one()
  }
  let neg_px = px.neg()
  let neg_qy = qy.neg()
  let t0 = TwistJac::from_affine(qx, qy)
  // MSB at index 65 is +1, index 64 is 0; evaluate step 64 directly to avoid 1 * 1 and mul by 1.
  let (t_init, a0, b0, c0) = line_double(t0, neg_px, py)
  let mut t = t_init
  let mut f = sparse_line_fp12(a0, b0, c0)
  for i = 63; i >= 0; i = i - 1 {
    f = f.sqr()
    let (t_dbl, ad, bd, cd) = line_double(t, neg_px, py)
    t = t_dbl
    f = f.mul_by_014(ad, bd, cd)
    let d = six_t_plus_2_naf[i]
    if d == 1 {
      let (t_add, aa, ba, ca) = line_add(t, qx, qy, neg_px, py)
      t = t_add
      f = f.mul_by_014(aa, ba, ca)
    } else if d == -1 {
      let (t_add, aa, ba, ca) = line_add(t, qx, neg_qy, neg_px, py)
      t = t_add
      f = f.mul_by_014(aa, ba, ca)
    }
  }
  // Final two Frobenius steps: add Q1 = pi_p(Q) and -Q2 = -pi_{p^2}(Q)
  let (q1x, q1y, neg_q2x, neg_q2y) = twist_frobenius_points(qx, qy)
  let (t_f1, af1, bf1, cf1) = line_add(t, q1x, q1y, neg_px, py)
  f = f.mul_by_014(af1, bf1, cf1)
  let (af2, bf2, cf2) = line_add_eval_only(t_f1, neg_q2x, neg_q2y, neg_px, py)
  f.mul_by_014(af2, bf2, cf2)
}

///|
/// Computes the joint two-pair Miller loop `miller_loop(Q1, P1) * miller_loop(Q2, P2)`
/// sharing all 65 `Fp12::sqr` squarings across both pairs.
fn miller_loop_2(
  q1x : @field.Fp2,
  q1y : @field.Fp2,
  p1x : @field.Fp,
  p1y : @field.Fp,
  q2x : @field.Fp2,
  q2y : @field.Fp2,
  p2x : @field.Fp,
  p2y : @field.Fp,
) -> @field.Fp12 {
  let neg_p1x = p1x.neg()
  let neg_q1y = q1y.neg()
  let neg_p2x = p2x.neg()
  let neg_q2y = q2y.neg()
  // Step i = 64 (six_t_plus_2_naf[64] == 0)
  let (t1_init, a1_0, b1_0, c1_0) = line_double(
    TwistJac::from_affine(q1x, q1y),
    neg_p1x,
    p1y,
  )
  let (t2_init, a2_0, b2_0, c2_0) = line_double(
    TwistJac::from_affine(q2x, q2y),
    neg_p2x,
    p2y,
  )
  let mut t1 = t1_init
  let mut t2 = t2_init
  let mut f = sparse_line_fp12(a1_0, b1_0, c1_0).mul_by_014(a2_0, b2_0, c2_0)
  for i = 63; i >= 0; i = i - 1 {
    f = f.sqr()
    let (t1_dbl, a1d, b1d, c1d) = line_double(t1, neg_p1x, p1y)
    t1 = t1_dbl
    f = f.mul_by_014(a1d, b1d, c1d)
    let (t2_dbl, a2d, b2d, c2d) = line_double(t2, neg_p2x, p2y)
    t2 = t2_dbl
    f = f.mul_by_014(a2d, b2d, c2d)
    let d = six_t_plus_2_naf[i]
    if d == 1 {
      let (t1_add, a1a, b1a, c1a) = line_add(t1, q1x, q1y, neg_p1x, p1y)
      t1 = t1_add
      f = f.mul_by_014(a1a, b1a, c1a)
      let (t2_add, a2a, b2a, c2a) = line_add(t2, q2x, q2y, neg_p2x, p2y)
      t2 = t2_add
      f = f.mul_by_014(a2a, b2a, c2a)
    } else if d == -1 {
      let (t1_add, a1a, b1a, c1a) = line_add(t1, q1x, neg_q1y, neg_p1x, p1y)
      t1 = t1_add
      f = f.mul_by_014(a1a, b1a, c1a)
      let (t2_add, a2a, b2a, c2a) = line_add(t2, q2x, neg_q2y, neg_p2x, p2y)
      t2 = t2_add
      f = f.mul_by_014(a2a, b2a, c2a)
    }
  }
  // Frobenius steps for pair 1
  let (q1_f1x, q1_f1y, q1_nf2x, q1_nf2y) = twist_frobenius_points(q1x, q1y)
  let (t1_f1, a1f1, b1f1, c1f1) = line_add(t1, q1_f1x, q1_f1y, neg_p1x, p1y)
  f = f.mul_by_014(a1f1, b1f1, c1f1)
  let (a1f2, b1f2, c1f2) = line_add_eval_only(
    t1_f1, q1_nf2x, q1_nf2y, neg_p1x, p1y,
  )
  f = f.mul_by_014(a1f2, b1f2, c1f2)
  // Frobenius steps for pair 2
  let (q2_f1x, q2_f1y, q2_nf2x, q2_nf2y) = twist_frobenius_points(q2x, q2y)
  let (t2_f1, a2f1, b2f1, c2f1) = line_add(t2, q2_f1x, q2_f1y, neg_p2x, p2y)
  f = f.mul_by_014(a2f1, b2f1, c2f1)
  let (a2f2, b2f2, c2f2) = line_add_eval_only(
    t2_f1, q2_nf2x, q2_nf2y, neg_p2x, p2y,
  )
  f.mul_by_014(a2f2, b2f2, c2f2)
}

///|
/// Computes the BN256 final exponentiation `f^((p^12 - 1) / N)` using the easy part
/// `(p^6 - 1)(p^2 + 1)` followed by the Fuentes-Castaneda / Scott-Devegili cyclotomic
/// addition chain for the hard part `(p^4 - p^2 + 1) / N`.
pub fn final_exponentiation(f : @field.Fp12) -> @field.Fp12 {
  if f.is_one() {
    return @field.Fp12::one()
  }
  if f.is_zero() {
    return @field.Fp12::zero()
  }
  // Easy part: f1 = f^((p^6 - 1)(p^2 + 1)) in G_{Phi_6}(Fp2)
  let f_easy1 = f.conjugate().mul(f.inv())
  let f1 = f_easy1.mul(f_easy1.frobenius_p2())
  // Hard part: f1^((p^4 - p^2 + 1) / N) using 3 cyclotomic_pow_t + 4 cyclotomic_sqr
  let fp = f1.frobenius_p()
  let fp2 = f1.frobenius_p2()
  let fp3 = fp2.frobenius_p()
  let y0 = fp.mul(fp2).mul(fp3)
  let fu = f1.cyclotomic_pow_t()
  let fu2 = fu.cyclotomic_pow_t()
  let fu3 = fu2.cyclotomic_pow_t()
  let y3 = fu.frobenius_p().conjugate()
  let fu2p = fu2.frobenius_p()
  let fu3p = fu3.frobenius_p()
  let y2 = fu2.frobenius_p2()
  let y1 = f1.conjugate()
  let y5 = fu2.conjugate()
  let y4 = fu.mul(fu2p).conjugate()
  let y6 = fu3.mul(fu3p).conjugate()
  let t0 = y6.cyclotomic_sqr().mul(y4).mul(y5)
  let t1 = y3.mul(y5).mul(t0)
  let t0 = t0.mul(y2)
  let t1 = t1.cyclotomic_sqr().mul(t0).cyclotomic_sqr()
  let t0 = t1.mul(y1)
  let t1 = t1.mul(y0)
  t0.cyclotomic_sqr().mul(t1)
}

///|
/// Computes the BN256 optimal R-ate bilinear pairing `e(Q, P) in GT` from affine coordinates
/// `Q = (qx, qy) in G2` and `P = (px, py) in G1`.
///
/// # Security Preconditions
/// Callers MUST ensure the input coordinates represent valid prime-order subgroup points
/// `Q in G2 \ {O}` (on `E'(Fp2)` with `[N]Q == O`) and `P in G1 \ {O}` (on `E(Fp)`),
/// or the explicit `(0, 0)` infinity sentinel. High-level callers should prefer typed
/// `@kgc.pair` or `@moonsm9.pair` with validated `G2Affine` / `G1Affine` points.
pub fn pair_coords(
  qx : @field.Fp2,
  qy : @field.Fp2,
  px : @field.Fp,
  py : @field.Fp,
) -> @field.Fp12 {
  if is_g2_zero(qx, qy) || is_g1_zero(px, py) {
    return @field.Fp12::one()
  }
  final_exponentiation(miller_loop(qx, qy, px, py))
}

///|
/// Computes the pairing product `e(Q1, P1) * e(Q2, P2) in GT` using a joint Miller loop
/// and a single shared final exponentiation.
///
/// # Security Preconditions
/// Callers MUST ensure both input pairs represent valid prime-order subgroup points
/// `Q1, Q2 in G2 \ {O}` (on `E'(Fp2)` with `[N]Q == O`) and `P1, P2 in G1 \ {O}` (on `E(Fp)`),
/// or the explicit `(0, 0)` infinity sentinel. High-level callers should prefer typed
/// `@kgc.pair` or `@moonsm9.pair` with validated `G2Affine` / `G1Affine` points.
pub fn pair_product_coords(
  q1x : @field.Fp2,
  q1y : @field.Fp2,
  p1x : @field.Fp,
  p1y : @field.Fp,
  q2x : @field.Fp2,
  q2y : @field.Fp2,
  p2x : @field.Fp,
  p2y : @field.Fp,
) -> @field.Fp12 {
  let first_zero = is_g2_zero(q1x, q1y) || is_g1_zero(p1x, p1y)
  let second_zero = is_g2_zero(q2x, q2y) || is_g1_zero(p2x, p2y)
  if first_zero && second_zero {
    return @field.Fp12::one()
  }
  if first_zero {
    return pair_coords(q2x, q2y, p2x, p2y)
  }
  if second_zero {
    return pair_coords(q1x, q1y, p1x, p1y)
  }
  final_exponentiation(miller_loop_2(q1x, q1y, p1x, p1y, q2x, q2y, p2x, p2y))
}
