///|
test "facade constants, utility helpers, and pairing infinity identities" {
  assert_eq(HID_SIGN, b'\x01')
  assert_eq(HID_KEYEX, b'\x02')
  assert_eq(HID_ENC, b'\x03')
  // SM3 standard vector "abc"
  assert_eq(
    sm3_hex(b"abc"),
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
  let digest = sm3_hash(b"abc")
  assert_eq(bytes_to_hex(digest), sm3_hex(b"abc"))
  let decoded = match hex_to_bytes(sm3_hex(b"abc")) {
    Some(b) => b
    None => abort("valid hex should decode")
  }
  assert_true(ct_eq_bytes(digest, decoded))
  // SM4-ECB-PKCS7 helper round-trip
  let sm4_key = match hex_to_bytes("0123456789abcdeffedcba9876543210") {
    Some(b) => b
    None => abort("valid key hex")
  }
  let pt = b"MoonSM9 facade SM4 check"
  let ct = match sm4_encrypt_ecb_pkcs7(sm4_key, pt) {
    Some(b) => b
    None => abort("sm4 encrypt failed")
  }
  assert_eq(sm4_decrypt_ecb_pkcs7(sm4_key, ct), Some(pt))
  // Pairing infinity identities for both pair and pair_product
  let p1 = @ec.G1Affine::generator()
  let p2 = @ec.G2Affine::generator()
  let g1_inf = @ec.G1Affine::identity()
  let g2_inf = @ec.G2Affine::identity()
  let e_base = pair(p2, p1)
  assert_eq(pair(g2_inf, p1), @field.Fp12::one())
  assert_eq(pair(p2, g1_inf), @field.Fp12::one())
  assert_eq(pair(g2_inf, g1_inf), @field.Fp12::one())
  assert_eq(pair_product(g2_inf, p1, p2, p1), e_base)
  assert_eq(pair_product(p2, g1_inf, p2, p1), e_base)
  assert_eq(pair_product(p2, p1, g2_inf, p1), e_base)
  assert_eq(pair_product(p2, p1, p2, g1_inf), e_base)
  assert_eq(pair_product(g2_inf, p1, p2, g1_inf), @field.Fp12::one())
}
