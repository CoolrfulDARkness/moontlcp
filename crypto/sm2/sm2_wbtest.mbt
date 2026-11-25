///|
test "F_p field arithmetic, Solinas reduction, inverse, and sqrt" {
  let p_minus_1 : U256 = {
    limbs: [
      0xFFFFFFFEU, 0xFFFFFFFFU, 0x00000000U, 0xFFFFFFFFU, 0xFFFFFFFFU, 0xFFFFFFFFU,
      0xFFFFFFFFU, 0xFFFFFFFEU,
    ],
  }
  // (p - 1) * (p - 1) === 1 (mod p)
  assert_true(u256_eq(fe_mul(p_minus_1, p_minus_1), u256_one()))
  // (p - 1) + 1 === 0 (mod p)
  assert_true(u256_is_zero(fe_add(p_minus_1, u256_one())))
  // 0 - 1 === p - 1 (mod p)
  assert_true(u256_eq(fe_sub(u256_zero(), u256_one()), p_minus_1))

  // Inverse & sqrt on base point coordinates
  let gx = u256_from_limbs(sm2_gx)
  let gy = u256_from_limbs(sm2_gy)
  assert_true(u256_eq(fe_mul(gx, fe_inv(gx)), u256_one()))
  assert_true(u256_eq(fe_mul(gy, fe_inv(gy)), u256_one()))
  assert_true(u256_eq(fe_mul(p_minus_1, fe_inv(p_minus_1)), u256_one()))

  let gy_sq = fe_sqr(gy)
  let root = fe_sqrt(gy_sq)
  assert_true(u256_eq(fe_sqr(root), gy_sq))
  assert_true(u256_eq(root, gy) || u256_eq(fe_neg(root), gy))
}

///|
test "F_n scalar arithmetic and Montgomery constants" {
  // Verify mont_r1_n == 2^256 mod n and mont_r2_n == 2^512 mod n by repeated doubling
  let mut cur = u256_one()
  for i = 0; i < 256; i = i + 1 {
    cur = sn_add(cur, cur)
  }
  assert_true(u256_eq(cur, u256_from_limbs(mont_r1_n)))
  for i = 0; i < 256; i = i + 1 {
    cur = sn_add(cur, cur)
  }
  assert_true(u256_eq(cur, u256_from_limbs(mont_r2_n)))

  // (n - 1)^2 === 1 (mod n) and inv(n - 1) == n - 1
  let nm1 = u256_from_limbs(sm2_n_minus_1)
  assert_true(u256_eq(sn_mul(nm1, nm1), u256_one()))
  assert_true(u256_eq(sn_inv(nm1), nm1))

  // Random scalar inverse check
  let s = u256_from_limbs(sm2_gx)
  assert_true(u256_eq(sn_mul(s, sn_inv(s)), u256_one()))
}

///|
test "SM2 curve group laws: (n-1)*G = -G, n*G = O, P+P = 2P, P+(-P) = O" {
  let g = sm2_generator()
  let nm1_g = scalar_mul_base(u256_from_limbs(sm2_n_minus_1))
  assert_false(nm1_g.is_inf)
  assert_true(u256_eq(nm1_g.x, g.x))
  assert_true(u256_eq(nm1_g.y, fe_neg(g.y)))

  // n * G = (n-1)*G + G = O
  let n_g = jac_to_affine(jac_add(jac_from_affine(nm1_g), jac_from_affine(g)))
  assert_true(n_g.is_inf)

  // jac_add(G, G) == jac_double(G)
  let g_jac = jac_from_affine(g)
  let add_gg = jac_to_affine(jac_add(g_jac, g_jac))
  let dbl_g = jac_to_affine(jac_double(g_jac))
  assert_false(add_gg.is_inf)
  assert_true(u256_eq(add_gg.x, dbl_g.x))
  assert_true(u256_eq(add_gg.y, dbl_g.y))
}
