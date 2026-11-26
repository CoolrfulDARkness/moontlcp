///|
fn wb_hex_nibble(c : Byte) -> Int32 {
  let v = c.to_int()
  if v >= 48 && v <= 57 {
    v - 48
  } else if v >= 97 && v <= 102 {
    v - 87
  } else if v >= 65 && v <= 70 {
    v - 55
  } else {
    -1
  }
}

///|
fn wb_hex_to_bytes(hex : Bytes) -> Bytes {
  let n = hex.length() / 2
  Bytes::makei(n, fn(i) {
    let hi = wb_hex_nibble(hex[i * 2])
    let lo = wb_hex_nibble(hex[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn wb_fp_from_hex(hex : Bytes) -> @field.Fp {
  match @field.Fp::from_be_bytes_strict(wb_hex_to_bytes(hex)) {
    Some(v) => v
    None => abort("invalid Fp hex")
  }
}

///|
test "Whitebox: cofactor point on E'(Fp2) satisfies is_on_curve but fails is_in_subgroup; cofactor clearing enters G2" {
  let cf_x = @field.Fp2::new(
    wb_fp_from_hex(
      b"0000000000000000000000000000000000000000000000000000000000000001",
    ),
    wb_fp_from_hex(
      b"0000000000000000000000000000000000000000000000000000000000000001",
    ),
  )
  let cf_y = @field.Fp2::new(
    wb_fp_from_hex(
      b"9782d17c0113ff75963b71b2afb4eb089a6c6ac94e599b48be78baaf3a5d5f96",
    ),
    wb_fp_from_hex(
      b"9324098b67dd1ccfb2bc8054215aaf13516d207bd61c4b8b3876c76edf7aa9ec",
    ),
  )
  let pt = match G2Affine::from_coords_on_curve_unchecked_subgroup(cf_x, cf_y) {
    Some(p) => p
    None => abort("expected cofactor point to lie on E'(Fp2)")
  }
  // On E'(Fp2), NOT in G2 subgroup!
  assert_true(pt.is_on_curve())
  assert_true(!pt.is_in_subgroup())
  assert_true(!pt.scalar_mul(@field.order_n).is_identity())
  // Strict API rejects it
  assert_true(G2Affine::from_coords_checked(cf_x, cf_y) is None)
  assert_true(G2Affine::from_bytes_raw_strict(pt.to_bytes_raw()) is None)
  // Multiplying by cofactor h2 = 2p - N clears the cofactor and lands in G2!
  let h2 = match
    @field.U256::from_be_bytes(
      wb_hex_to_bytes(
        b"b640000002a3a6f1d603ab4ff58ec745f9f2934b1c0b51c8e57054b2f003bbd5",
      ),
    ) {
    Some(v) => v
    None => abort("invalid h2")
  }
  let cleared = pt.scalar_mul(h2).to_affine()
  assert_true(!cleared.is_infinity())
  assert_true(cleared.is_on_curve())
  assert_true(cleared.is_in_subgroup())
  assert_eq(
    G2Affine::from_bytes_raw_strict(cleared.to_bytes_raw()),
    Some(cleared),
  )
  // Wrong-twist point is rejected even by unchecked-subgroup helper
  let wt_x = @field.Fp2::new(
    wb_fp_from_hex(
      b"0000000000000000000000000000000000000000000000000000000000000002",
    ),
    wb_fp_from_hex(
      b"0000000000000000000000000000000000000000000000000000000000000001",
    ),
  )
  let wt_y = @field.Fp2::new(
    wb_fp_from_hex(
      b"718da4efb433867d47e25eeb9706c91c429177370bc52c19e72086bc07d630be",
    ),
    wb_fp_from_hex(
      b"64430ad9bb77e6a1e74108282f7a6631946a0764171c1e7e41cabcd2844c125f",
    ),
  )
  assert_true(
    G2Affine::from_coords_on_curve_unchecked_subgroup(wt_x, wt_y) is None,
  )
}
