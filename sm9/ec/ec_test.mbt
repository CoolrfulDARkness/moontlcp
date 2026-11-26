///|
fn hex_nibble(c : Byte) -> Int32 {
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
fn hex_to_bytes(hex : Bytes) -> Bytes {
  let n = hex.length() / 2
  Bytes::makei(n, fn(i) {
    let hi = hex_nibble(hex[i * 2])
    let lo = hex_nibble(hex[i * 2 + 1])
    ((hi << 4) | lo).to_byte()
  })
}

///|
fn bytes_to_hex(b : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i = 0; i < b.length(); i = i + 1 {
    let v = b[i].to_int()
    buf.write_char(digits[(v >> 4) & 0xF].to_int().unsafe_to_char())
    buf.write_char(digits[v & 0xF].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
fn u256_from_hex(hex : Bytes) -> @field.U256 {
  match @field.U256::from_be_bytes(hex_to_bytes(hex)) {
    Some(v) => v
    None => abort("invalid U256 hex")
  }
}

///|
fn fn_from_hex(hex : Bytes) -> @field.Fn {
  match @field.Fn::from_be_bytes_strict(hex_to_bytes(hex)) {
    Some(v) => v
    None => abort("invalid Fn hex")
  }
}

///|
fn fp_from_hex(hex : Bytes) -> @field.Fp {
  match @field.Fp::from_be_bytes_strict(hex_to_bytes(hex)) {
    Some(v) => v
    None => abort("invalid Fp hex")
  }
}

///|
test "Generators P1 and P2 match GB/T 38635.5 exact coordinates" {
  let p1 = @ec.G1Affine::generator()
  assert_true(!p1.is_infinity())
  assert_true(p1.is_on_curve())
  assert_eq(
    bytes_to_hex(p1.to_bytes_raw()),
    "93de051d62bf718ff5ed0704487d01d6e1e4086909dc3280e8c4e4817c66dddd21fe8dda4f21e607631065125c395bbc1c1c00cbfa6024350c464cd70a3ea616",
  )
  let p2 = @ec.G2Affine::generator()
  assert_true(!p2.is_infinity())
  assert_true(p2.is_on_curve())
  assert_true(p2.is_in_subgroup())
  assert_eq(
    bytes_to_hex(p2.to_bytes_raw()),
    "85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d88061413722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65b17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96a7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7",
  )
}

///|
test "G1 group axioms, complete CT addition, mixed addition, and order N" {
  let p = @ec.G1Jac::generator()
  let p_aff = @ec.G1Affine::generator()
  let inf = @ec.G1Jac::identity()
  let inf_aff = @ec.G1Affine::identity()
  // Identity laws
  assert_true(inf.is_identity())
  assert_true(inf_aff.is_infinity())
  assert_true(inf_aff.is_on_curve())
  assert_eq(inf.double(), inf)
  assert_eq(inf.add(inf), inf)
  assert_eq(inf.add(p), p)
  assert_eq(p.add(inf), p)
  assert_eq(inf.add_mixed(inf_aff), inf)
  assert_eq(inf.add_mixed(p_aff), p)
  assert_eq(p.add_mixed(inf_aff), p)
  assert_eq(inf.to_affine(), inf_aff)
  assert_eq(inf_aff.to_jac(), inf)
  // Inverse and doubling via add / add_mixed
  let neg_p = p.neg()
  let neg_p_aff = p_aff.neg()
  assert_eq(p.add(neg_p), inf)
  assert_eq(neg_p.add(p), inf)
  assert_eq(p.add_mixed(neg_p_aff), inf)
  assert_eq(p.sub(p), inf)
  let p2 = p.double()
  assert_eq(p.add(p), p2)
  assert_eq(p.add_mixed(p_aff), p2)
  let p2_aff = p2.to_affine()
  assert_true(p2_aff.is_on_curve())
  assert_eq(p2.add_mixed(p2_aff), p2.double())
  assert_eq(p2.add_mixed(p2_aff.neg()), inf)
  // Associativity and small multiples
  let p3 = p2.add(p)
  let p4 = p2.double()
  let p5 = p3.add(p2)
  let p5_alt = p4.add_mixed(p_aff)
  assert_eq(p5, p5_alt)
  assert_eq(p5.to_affine(), p5_alt.to_affine())
  assert_eq(p.scalar_mul(@field.U256::zero()), inf)
  assert_eq(p.scalar_mul(@field.U256::one()), p)
  assert_eq(p.scalar_mul(@field.U256::from_u64(2UL)), p2)
  assert_eq(p.scalar_mul(@field.U256::from_u64(5UL)), p5)
  assert_eq(
    p.scalar_mul(@field.U256::from_u64(15UL)).add(p),
    p.scalar_mul(@field.U256::from_u64(16UL)),
  )
  assert_eq(
    p.scalar_mul(@field.U256::from_u64(17UL)),
    p.scalar_mul(@field.U256::from_u64(16UL)).add(p),
  )
  assert_eq(inf.scalar_mul(@field.U256::from_u64(12345UL)), inf)
  // [a+b]P == [a]P + [b]P and [a]([b]P) == [a*b]P
  let a = @field.Fn::from_u64(0x123456789abcdef1UL)
  let b = @field.Fn::from_u64(0xfedcba9876543219UL)
  assert_eq(
    p.scalar_mul_fn(a.add(b)),
    p.scalar_mul_fn(a).add(p.scalar_mul_fn(b)),
  )
  assert_eq(p.scalar_mul_fn(b).scalar_mul_fn(a), p.scalar_mul_fn(a.mul(b)))
  // Order N checks: [N]P1 == O and [N-1]P1 == -P1
  assert_true(p.scalar_mul(@field.order_n).is_identity())
  let n_minus_1 = @field.Fn::zero().sub(@field.Fn::one())
  assert_eq(p_aff.scalar_mul_fn(n_minus_1), neg_p)
  // ct_select checks
  let mask0 = @field.ct_mask(false)
  let mask1 = @field.ct_mask(true)
  assert_eq(@ec.G1Jac::ct_select(p, p2, mask0), p)
  assert_eq(@ec.G1Jac::ct_select(p, p2, mask1), p2)
  assert_eq(@ec.G1Affine::ct_select(p_aff, inf_aff, mask0), p_aff)
  assert_eq(@ec.G1Affine::ct_select(p_aff, inf_aff, mask1), inf_aff)
}

///|
test "G2 group axioms, complete CT addition, mixed addition, and order N" {
  let q = @ec.G2Jac::generator()
  let q_aff = @ec.G2Affine::generator()
  let inf = @ec.G2Jac::identity()
  let inf_aff = @ec.G2Affine::identity()
  // Identity laws
  assert_true(inf.is_identity())
  assert_true(inf_aff.is_infinity())
  assert_true(inf_aff.is_on_curve())
  assert_true(inf_aff.is_in_subgroup())
  assert_eq(inf.double(), inf)
  assert_eq(inf.add(inf), inf)
  assert_eq(inf.add(q), q)
  assert_eq(q.add(inf), q)
  assert_eq(inf.add_mixed(inf_aff), inf)
  assert_eq(inf.add_mixed(q_aff), q)
  assert_eq(q.add_mixed(inf_aff), q)
  assert_eq(inf.to_affine(), inf_aff)
  assert_eq(inf_aff.to_jac(), inf)
  // Inverse and doubling
  let neg_q = q.neg()
  let neg_q_aff = q_aff.neg()
  assert_eq(q.add(neg_q), inf)
  assert_eq(neg_q.add(q), inf)
  assert_eq(q.add_mixed(neg_q_aff), inf)
  assert_eq(q.sub(q), inf)
  let q2 = q.double()
  assert_eq(q.add(q), q2)
  assert_eq(q.add_mixed(q_aff), q2)
  let q2_aff = q2.to_affine()
  assert_true(q2_aff.is_on_curve())
  assert_eq(q2.add_mixed(q2_aff), q2.double())
  assert_eq(q2.add_mixed(q2_aff.neg()), inf)
  // Small multiples and linearity
  let q5 = q2.add(q).add(q2)
  assert_eq(q.scalar_mul(@field.U256::zero()), inf)
  assert_eq(q.scalar_mul(@field.U256::one()), q)
  assert_eq(q.scalar_mul(@field.U256::from_u64(5UL)), q5)
  assert_eq(inf.scalar_mul(@field.U256::from_u64(99UL)), inf)
  let a = @field.Fn::from_u64(0x0102030405060708UL)
  let b = @field.Fn::from_u64(0x1122334455667788UL)
  assert_eq(
    q.scalar_mul_fn(a.add(b)),
    q.scalar_mul_fn(a).add(q.scalar_mul_fn(b)),
  )
  // Order N checks: [N]P2 == O and [N-1]P2 == -P2
  assert_true(q.scalar_mul(@field.order_n).is_identity())
  let n_minus_1 = @field.Fn::zero().sub(@field.Fn::one())
  assert_eq(q_aff.scalar_mul_fn(n_minus_1), neg_q)
  // ct_select checks
  let mask0 = @field.ct_mask(false)
  let mask1 = @field.ct_mask(true)
  assert_eq(@ec.G2Jac::ct_select(q, q2, mask0), q)
  assert_eq(@ec.G2Jac::ct_select(q, q2, mask1), q2)
  assert_eq(@ec.G2Affine::ct_select(q_aff, inf_aff, mask0), q_aff)
  assert_eq(@ec.G2Affine::ct_select(q_aff, inf_aff, mask1), inf_aff)
}

///|
test "GB/T 38635.2 (Part 2 Signature) exact scalar multiplication vectors" {
  let ks = fn_from_hex(
    b"000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4",
  )
  let p_pub_s = @ec.G2Affine::generator().scalar_mul_fn(ks).to_affine()
  assert_eq(
    bytes_to_hex(p_pub_s.to_bytes_raw()),
    "9f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c40829dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e3269850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c2541e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d",
  )
  assert_true(p_pub_s.is_in_subgroup())
  let t2 = fn_from_hex(
    b"291fe3cac8f58ad2dc462c8d4d578a94dafd5624ddc28e328d2936688a86cf1a",
  )
  let ds_a = @ec.G1Affine::generator().scalar_mul_fn(t2).to_affine()
  assert_eq(
    bytes_to_hex(ds_a.to_bytes_raw()),
    "a5702f05cf1315305e2d6eb64b0deb923db1a0bcf0caff90523ac8754aa6982078559a844411f9825c109f5ee3f52d720dd01785392a727bb1556952b2b013d3",
  )
  let l = fn_from_hex(
    b"3406f1643496dff8385c82cf5f4442b0123e89abaf898013fb13ae36d9799108",
  )
  let sig_s = ds_a.scalar_mul_fn(l).to_affine()
  assert_eq(
    bytes_to_hex(sig_s.to_bytes_raw()),
    "73bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05",
  )
}

///|
test "GB/T 38635.3 (Part 3 Key Exchange) exact scalar multiplication vectors" {
  let ke = fn_from_hex(
    b"0002e65b0762d042f51f0d23542b13ed8cfa2e9a0e7206361e013a283905e31f",
  )
  let p_pub_e = @ec.G1Affine::generator().scalar_mul_fn(ke).to_affine()
  assert_eq(
    bytes_to_hex(p_pub_e.to_bytes_raw()),
    "9174542668e8f14ab273c0945c3690c66e5dd09678b86f734c4350567ed0628354e598c6bf749a3dacc9fffedd9db6866c50457cfc7aa2a4ad65c3168ff74210",
  )
  let h1_a = fn_from_hex(
    b"a9ac0fda7380ed8e3325fddcd40a7221e3cd72f6ffa7f27d54ad494cedb4e212",
  )
  let h1_b = fn_from_hex(
    b"56af6ef1d2ab38f1ee77a5d538dd33b44917f2d9ad6ab68a993b36c727ed9838",
  )
  let t2_a = match h1_a.add(ke).inv() {
    Some(inv) => ke.mul(inv)
    None => abort("unexpected zero t1_A")
  }
  let t2_b = match h1_b.add(ke).inv() {
    Some(inv) => ke.mul(inv)
    None => abort("unexpected zero t1_B")
  }
  let de_a = @ec.G2Affine::generator().scalar_mul_fn(t2_a).to_affine()
  assert_eq(
    bytes_to_hex(de_a.to_bytes_raw()),
    "0fe8eab395199b56bf1d75bd2cd610b6424f08d1092922c5882b52dcd6ca832a7da57bc50241f9e5bfddc075dd9d32c7777100d736916cfc165d8d36e0634cd783a457daf52cad464c903b26062caf937bb40e37daded9eda401050e49c8ad0c6970876b9aad1b7a50bb4863a11e574af1fe3c5975161d73de4c3af621fb1efb",
  )
  let de_b = @ec.G2Affine::generator().scalar_mul_fn(t2_b).to_affine()
  assert_eq(
    bytes_to_hex(de_b.to_bytes_raw()),
    "74ccc3ac9c383c60af083972b96d05c75f12c8907d128a17adafbab8c5a4acf701092ff4de89362670c21711b6dbe52dcd5f8e40c6654b3dece573c2ab3d29b244b0294aa04290e1524ff3e3da8cfd432bb64de3a8040b5b88d1b5fc86a4ebc18cfc48fb4ff37f1e27727464f3c34e2153861ad08e972d1625fc1a7bd18d5539",
  )
  let q_b = @ec.G1Affine::generator()
    .scalar_mul_fn(h1_b)
    .add_mixed(p_pub_e)
    .to_affine()
  assert_eq(
    bytes_to_hex(q_b.to_bytes_raw()),
    "a1c5ea63ae85302b026c2ee86dc7e8802ce3083061571fc98747011ce088bbd7635385a8f01c8e73720ca4ad5de8125810b6271c84b27ec6eab182c6266e4da2",
  )
  let r_a = fn_from_hex(
    b"00005879dd1d51e175946f23b1b41e93ba31c584ae59a426ec1046a4d03b06c8",
  )
  let pt_ra = q_b.scalar_mul_fn(r_a).to_affine()
  assert_eq(
    bytes_to_hex(pt_ra.to_bytes_raw()),
    "7cba5b19069ee66aa79d490413d11846b9ba76dd22567f809cf23b6d964bb265a9760c99cb6f706343fed05637085864958d6c90902aba7d405fbedf7b781599",
  )
  let q_a = @ec.G1Affine::generator()
    .scalar_mul_fn(h1_a)
    .add_mixed(p_pub_e)
    .to_affine()
  assert_eq(
    bytes_to_hex(q_a.to_bytes_raw()),
    "66c68126e6c3e19769a203c0c3275cf9121a4a116d7851da9a702a3e14f679dd52af31f245eb74cde62f99a2b557b6219c53c3f3ba7b21e1fdc62ea4bcff9795",
  )
  let r_b = fn_from_hex(
    b"00018b98c44bef9f8537fb7d071b2c928b3bc65bd3d69e1eee213564905634fe",
  )
  let pt_rb = q_a.scalar_mul_fn(r_b).to_affine()
  assert_eq(
    bytes_to_hex(pt_rb.to_bytes_raw()),
    "861e91485fb7623d2794f495031a35598b493bd45be37813abc710fcc1f3448232d906a469ebc1216a802a7052d5617cd430fb56fba729d41d9bd668e9eb9600",
  )
}

///|
test "GB/T 38635.4 (Part 4 KEM/PKE A.1 & A.2) exact scalar multiplication vectors" {
  let ke = fn_from_hex(
    b"0001edee3778f441f8dea3d9fa0acc4e07ee36c93f9a08618af4ad85cede1c22",
  )
  let p_pub_e = @ec.G1Affine::generator().scalar_mul_fn(ke).to_affine()
  assert_eq(
    bytes_to_hex(p_pub_e.to_bytes_raw()),
    "787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1",
  )
  let h1_b = fn_from_hex(
    b"9cb1f6288ce0e51043ce72344582ffc301e0a812a7f5f2004b85547a24b82716",
  )
  let t2_b = match h1_b.add(ke).inv() {
    Some(inv) => ke.mul(inv)
    None => abort("unexpected zero t1_B")
  }
  let de_b = @ec.G2Affine::generator().scalar_mul_fn(t2_b).to_affine()
  assert_eq(
    bytes_to_hex(de_b.to_bytes_raw()),
    "94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b1587aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1",
  )
  let q_b = @ec.G1Affine::generator()
    .scalar_mul_fn(h1_b)
    .add_mixed(p_pub_e)
    .to_affine()
  assert_eq(
    bytes_to_hex(q_b.to_bytes_raw()),
    "709d165808b0a43e2574e203fa885abcbab16a240c4c1916552e7c43d09763b8693269a6be2456f43333758274786b6051ff87b7f198da4ba1a2c6e336f51fcc",
  )
  // Appendix A.1 KEM
  let r_a1 = fn_from_hex(
    b"000074015f8489c01ef4270456f9e6475bfb602bde7f33fd482ab4e3684a6722",
  )
  let c1_a1 = q_b.scalar_mul_fn(r_a1).to_affine()
  assert_eq(
    bytes_to_hex(c1_a1.to_bytes_raw()),
    "1edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c",
  )
  // Appendix A.2 PKE
  let r_a2 = fn_from_hex(
    b"0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )
  let c1_a2 = q_b.scalar_mul_fn(r_a2).to_affine()
  assert_eq(
    bytes_to_hex(c1_a2.to_bytes_raw()),
    "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0",
  )
}

///|
test "G1 and G2 serialization round-trips (raw, uncompressed, compressed)" {
  let p1 = @ec.G1Affine::generator()
  let neg_p1 = p1.neg()
  // P1 has even y (...a616), -P1 has odd y (p is odd, so p - even is odd)
  let g1_pts : FixedArray[@ec.G1Affine] = [
    p1,
    neg_p1,
    p1.scalar_mul(@field.U256::from_u64(7UL)).to_affine(),
    p1.scalar_mul(@field.U256::from_u64(42UL)).to_affine(),
  ]
  for i = 0; i < g1_pts.length(); i = i + 1 {
    let pt = g1_pts[i]
    let raw = pt.to_bytes_raw()
    assert_eq(raw.length(), 64)
    assert_eq(@ec.G1Affine::from_bytes_raw_strict(raw), Some(pt))
    let unc = pt.to_bytes_uncompressed()
    assert_eq(unc.length(), 65)
    assert_eq(unc[0], b'\x04')
    assert_eq(@ec.G1Affine::from_bytes_uncompressed_strict(unc), Some(pt))
    let cmp = pt.to_bytes_compressed()
    assert_eq(cmp.length(), 33)
    assert_true(cmp[0] == b'\x02' || cmp[0] == b'\x03')
    assert_eq(@ec.G1Affine::from_bytes_compressed_strict(cmp), Some(pt))
  }
  assert_eq(p1.to_bytes_compressed()[0], b'\x02')
  assert_eq(neg_p1.to_bytes_compressed()[0], b'\x03')
  // G2 round-trips
  let p2 = @ec.G2Affine::generator()
  let g2_pts : FixedArray[@ec.G2Affine] = [
    p2,
    p2.neg(),
    p2.scalar_mul(@field.U256::from_u64(13UL)).to_affine(),
  ]
  for i = 0; i < g2_pts.length(); i = i + 1 {
    let pt = g2_pts[i]
    let raw = pt.to_bytes_raw()
    assert_eq(raw.length(), 128)
    assert_eq(@ec.G2Affine::from_bytes_raw_strict(raw), Some(pt))
    let unc = pt.to_bytes_uncompressed()
    assert_eq(unc.length(), 129)
    assert_eq(unc[0], b'\x04')
    assert_eq(@ec.G2Affine::from_bytes_uncompressed_strict(unc), Some(pt))
  }
  // Infinity encodings are rejected by all strict decoders
  let g1_inf = @ec.G1Affine::identity()
  assert_eq(g1_inf.to_bytes_raw(), Bytes::make(64, b'\x00'))
  assert_eq(g1_inf.to_bytes_compressed(), Bytes::make(33, b'\x00'))
  assert_true(
    @ec.G1Affine::from_bytes_raw_strict(g1_inf.to_bytes_raw()) is None,
  )
  assert_true(
    @ec.G1Affine::from_bytes_uncompressed_strict(g1_inf.to_bytes_uncompressed())
    is None,
  )
  assert_true(
    @ec.G1Affine::from_bytes_compressed_strict(g1_inf.to_bytes_compressed())
    is None,
  )
  let g2_inf = @ec.G2Affine::identity()
  assert_eq(g2_inf.to_bytes_raw(), Bytes::make(128, b'\x00'))
  assert_true(
    @ec.G2Affine::from_bytes_raw_strict(g2_inf.to_bytes_raw()) is None,
  )
  assert_true(
    @ec.G2Affine::from_bytes_uncompressed_strict(g2_inf.to_bytes_uncompressed())
    is None,
  )
}

///|
test "Adversarial & malformed inputs: off-curve, out-of-range, wrong prefix, wrong twist, cofactor G2" {
  let p1 = @ec.G1Affine::generator()
  // 1. Off-curve G1 point (x_P1, y_P1 + 1)
  assert_true(
    @ec.G1Affine::from_coords_checked(p1.x(), p1.y().add(@field.Fp::one()))
    is None,
  )
  assert_true(
    @ec.G1Affine::from_coords_checked(@field.Fp::zero(), @field.Fp::zero())
    is None,
  )
  // 2. Out-of-range (>= p) coordinates for G1
  let p_bytes = @field.modulus_p.to_be_bytes()
  let bad_g1_raw = Bytes::makei(64, fn(i) {
    if i < 32 {
      p_bytes[i]
    } else {
      p1.y().to_be_bytes()[i - 32]
    }
  })
  assert_true(@ec.G1Affine::from_bytes_raw_strict(bad_g1_raw) is None)
  let bad_g1_cmp = Bytes::makei(33, fn(i) {
    if i == 0 {
      b'\x02'
    } else {
      p_bytes[i - 1]
    }
  })
  assert_true(@ec.G1Affine::from_bytes_compressed_strict(bad_g1_cmp) is None)
  // 3. Wrong lengths and prefixes for G1
  let p1_unc = p1.to_bytes_uncompressed()
  let bad_prefix_unc = Bytes::makei(65, fn(i) {
    if i == 0 {
      b'\x05'
    } else {
      p1_unc[i]
    }
  })
  assert_true(
    @ec.G1Affine::from_bytes_uncompressed_strict(bad_prefix_unc) is None,
  )
  assert_true(
    @ec.G1Affine::from_bytes_raw_strict(Bytes::make(63, b'\x01')) is None,
  )
  assert_true(
    @ec.G1Affine::from_bytes_uncompressed_strict(Bytes::make(64, b'\x04'))
    is None,
  )
  assert_true(
    @ec.G1Affine::from_bytes_compressed_strict(Bytes::make(32, b'\x02')) is None,
  )
  let p1_cmp = p1.to_bytes_compressed()
  let bad_prefix_cmp = Bytes::makei(33, fn(i) {
    if i == 0 {
      b'\x04'
    } else {
      p1_cmp[i]
    }
  })
  assert_true(
    @ec.G1Affine::from_bytes_compressed_strict(bad_prefix_cmp) is None,
  )
  // 4. Compressed G1 with x where x^3 + 5 is a quadratic non-residue
  let mut found_qnr = false
  for k = 0UL; k < 30UL; k = k + 1UL {
    let x = @field.Fp::from_u64(k)
    let rhs = x.sqr().mul(x).add(@field.Fp::b_const())
    if rhs.sqrt() is None {
      let xb = x.to_be_bytes()
      let qnr_cmp = Bytes::makei(33, fn(i) {
        if i == 0 {
          b'\x02'
        } else {
          xb[i - 1]
        }
      })
      assert_true(@ec.G1Affine::from_bytes_compressed_strict(qnr_cmp) is None)
      found_qnr = true
      break
    }
  }
  assert_true(found_qnr)
  // 5. Wrong-twist G2 point on y^2 = x^3 + 5/u (must be rejected!)
  let wt_x1 = fp_from_hex(
    b"0000000000000000000000000000000000000000000000000000000000000001",
  )
  let wt_x0 = fp_from_hex(
    b"0000000000000000000000000000000000000000000000000000000000000002",
  )
  let wt_y1 = fp_from_hex(
    b"64430ad9bb77e6a1e74108282f7a6631946a0764171c1e7e41cabcd2844c125f",
  )
  let wt_y0 = fp_from_hex(
    b"718da4efb433867d47e25eeb9706c91c429177370bc52c19e72086bc07d630be",
  )
  let wt_x = @field.Fp2::new(wt_x0, wt_x1)
  let wt_y = @field.Fp2::new(wt_y0, wt_y1)
  // Confirm it truly lies on y^2 = x^3 + 5/u (not 5u)
  let five_over_u = @field.Fp2::from_fp(@field.Fp::b_const()).mul(
    @field.Fp2::new(@field.Fp::zero(), @field.Fp::one()).inv(),
  )
  assert_eq(wt_y.sqr(), wt_x.sqr().mul(wt_x).add(five_over_u))
  assert_true(@ec.G2Affine::from_coords_checked(wt_x, wt_y) is None)
  let wt_raw = hex_to_bytes(
    b"0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000264430ad9bb77e6a1e74108282f7a6631946a0764171c1e7e41cabcd2844c125f718da4efb433867d47e25eeb9706c91c429177370bc52c19e72086bc07d630be",
  )
  assert_true(@ec.G2Affine::from_bytes_raw_strict(wt_raw) is None)
  // 6. Cofactor G2 point: ON E'(Fp2): y^2 = x^3 + 5u, but NOT in prime-order G2 subgroup!
  let cf_x1 = fp_from_hex(
    b"0000000000000000000000000000000000000000000000000000000000000001",
  )
  let cf_x0 = fp_from_hex(
    b"0000000000000000000000000000000000000000000000000000000000000001",
  )
  let cf_y1 = fp_from_hex(
    b"9324098b67dd1ccfb2bc8054215aaf13516d207bd61c4b8b3876c76edf7aa9ec",
  )
  let cf_y0 = fp_from_hex(
    b"9782d17c0113ff75963b71b2afb4eb089a6c6ac94e599b48be78baaf3a5d5f96",
  )
  let cf_x = @field.Fp2::new(cf_x0, cf_x1)
  let cf_y = @field.Fp2::new(cf_y0, cf_y1)
  // Verify curve equation holds: y^2 == x^3 + 5u
  assert_eq(cf_y.sqr(), cf_x.sqr().mul(cf_x).add(@field.Fp2::b_twist()))
  // Strict constructor and decoders MUST reject it!
  assert_true(@ec.G2Affine::from_coords_checked(cf_x, cf_y) is None)
  let cf_raw = hex_to_bytes(
    b"000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000019324098b67dd1ccfb2bc8054215aaf13516d207bd61c4b8b3876c76edf7aa9ec9782d17c0113ff75963b71b2afb4eb089a6c6ac94e599b48be78baaf3a5d5f96",
  )
  assert_true(@ec.G2Affine::from_bytes_raw_strict(cf_raw) is None)
  let cf_unc = Bytes::makei(129, fn(i) {
    if i == 0 {
      b'\x04'
    } else {
      cf_raw[i - 1]
    }
  })
  assert_true(@ec.G2Affine::from_bytes_uncompressed_strict(cf_unc) is None)
  // 7. G2 out-of-range (>= p), wrong prefix, wrong length
  let p2_raw = @ec.G2Affine::generator().to_bytes_raw()
  let bad_g2_raw = Bytes::makei(128, fn(i) {
    if i < 32 {
      p_bytes[i]
    } else {
      p2_raw[i]
    }
  })
  assert_true(@ec.G2Affine::from_bytes_raw_strict(bad_g2_raw) is None)
  let bad_g2_unc = Bytes::makei(129, fn(i) {
    if i == 0 {
      b'\x02'
    } else {
      p2_raw[i - 1]
    }
  })
  assert_true(@ec.G2Affine::from_bytes_uncompressed_strict(bad_g2_unc) is None)
  assert_true(
    @ec.G2Affine::from_bytes_raw_strict(Bytes::make(127, b'\x01')) is None,
  )
  // Verify u256_from_hex helper is exercised with h2
  let h2 = u256_from_hex(
    b"b640000002a3a6f1d603ab4ff58ec745f9f2934b1c0b51c8e57054b2f003bbd5",
  )
  assert_true(!h2.is_zero())
}
