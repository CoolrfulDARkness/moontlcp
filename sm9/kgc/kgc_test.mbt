///|
fn must_hex(hex : String) -> Bytes {
  match @sm3.hex_to_bytes(hex) {
    Some(b) => b
    None => abort("invalid hex literal in test")
  }
}

///|
test "GB/T 38635.2 (Part 2) official KGC vectors: P_pub-s, H1, ds_A, g" {
  assert_eq(@kgc.HID_SIGN, b'\x01')
  assert_eq(@kgc.HID_KEYEX, b'\x02')
  assert_eq(@kgc.HID_ENC, b'\x03')
  let ks_hex = "000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4"
  let master = match
    @kgc.SignMasterPrivateKey::from_bytes_strict(must_hex(ks_hex)) {
    Some(k) => k
    None => abort("valid Part 2 ks rejected")
  }
  assert_eq(@sm3.bytes_to_hex(master.to_bytes()), ks_hex)
  assert_eq(@sm3.bytes_to_hex(master.scalar().to_be_bytes()), ks_hex)
  // P_pub-s = [ks]P2 (128B raw: x1 || x0 || y1 || y0)
  let p_pub_s = master.public_key()
  let expected_p_pub_s = "9f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c408" +
    "29dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e32" +
    "69850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c25" +
    "41e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d"
  assert_eq(@sm3.bytes_to_hex(p_pub_s.to_bytes_raw()), expected_p_pub_s)
  assert_eq(
    @sm3.bytes_to_hex(p_pub_s.to_bytes_uncompressed()),
    "04" + expected_p_pub_s,
  )
  // H1("Alice" || 0x01, N)
  let h1 = @kgc.h1_scalar(b"Alice", @kgc.HID_SIGN)
  assert_eq(
    @sm3.bytes_to_hex(h1.to_be_bytes()),
    "2acc468c3926b0bdb2767e99ff26e084de9ced8dbc7d5fbf418027b667862fab",
  )
  // ds_A = [ks * (H1 + ks)^-1 mod N]P1 (64B raw: x || y)
  let ds_a = match @kgc.extract_sign_private_key(master, b"Alice") {
    Ok(k) => k
    Err(e) => abort("extract_sign_private_key failed: " + e)
  }
  let expected_ds_a = "a5702f05cf1315305e2d6eb64b0deb923db1a0bcf0caff90523ac8754aa69820" +
    "78559a844411f9825c109f5ee3f52d720dd01785392a727bb1556952b2b013d3"
  assert_eq(@sm3.bytes_to_hex(ds_a.to_bytes_raw()), expected_ds_a)
  assert_eq(
    @sm3.bytes_to_hex(ds_a.to_bytes_uncompressed()),
    "04" + expected_ds_a,
  )
  // g = e(P_pub-s, P1) (384B)
  let g = p_pub_s.precompute_g()
  let expected_g = "4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d" +
    "28b3404a61908f5d6198815c99af1990c8af38655930058c28c21bb539ce0000" +
    "38bffe40a22d529a0c66124b2c308dac9229912656f62b4facfced408e02380f" +
    "a01f2c8bee81769609462c69c96aa923fd863e209d3ce26dd889b55e2e3873db" +
    "67e0e0c2eed7a6993dce28fe9aa2ef56834307860839677f96685f2b44d0911f" +
    "5a1ae172102efd95df7338dbc577c66d8d6c15e0a0158c7507228efb078f42a6" +
    "1604a3fcfa9783e667ce9fcb1062c2a5c6685c316dda62de0548baa6ba30038b" +
    "93634f44fa13af76169f3cc8fbea880adaff8475d5fd28a75deb83c44362b439" +
    "b3129a75d31d17194675a1bc56947920898fbf390a5bf5d931ce6cbb3340f66d" +
    "4c744e69c4a2e1c8ed72f796d151a17ce2325b943260fc460b9f73cb57c9014b" +
    "84b87422330d7936eaba1109fa5a7a7181ee16f2438b0aeb2f38fd5f7554e57a" +
    "aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb"
  assert_eq(@sm3.bytes_to_hex(g.to_bytes()), expected_g)
  // User signing public point P_A = [H1]P2 + P_pub-s satisfies e(P_A, ds_A) == g
  let p_a = @kgc.derive_sign_user_public_point(p_pub_s, b"Alice")
  assert_true(!p_a.is_infinity())
  assert_true(p_a.is_on_curve())
  assert_true(p_a.is_in_subgroup())
  assert_eq(@kgc.pair(p_a, ds_a.to_g1()), g)
}

///|
test "GB/T 38635.3 (Part 3) official KGC vectors: P_pub-e, de_A, de_B, Q_A, Q_B" {
  let ke_hex = "0002e65b0762d042f51f0d23542b13ed8cfa2e9a0e7206361e013a283905e31f"
  let master = match
    @kgc.EncMasterPrivateKey::from_bytes_strict(must_hex(ke_hex)) {
    Some(k) => k
    None => abort("valid Part 3 ke rejected")
  }
  assert_eq(@sm3.bytes_to_hex(master.to_bytes()), ke_hex)
  assert_eq(@sm3.bytes_to_hex(master.scalar().to_be_bytes()), ke_hex)
  // P_pub-e = [ke]P1 (64B raw)
  let p_pub_e = master.public_key()
  let expected_p_pub_e = "9174542668e8f14ab273c0945c3690c66e5dd09678b86f734c4350567ed06283" +
    "54e598c6bf749a3dacc9fffedd9db6866c50457cfc7aa2a4ad65c3168ff74210"
  assert_eq(@sm3.bytes_to_hex(p_pub_e.to_bytes_raw()), expected_p_pub_e)
  assert_eq(
    @sm3.bytes_to_hex(p_pub_e.to_bytes_uncompressed()),
    "04" + expected_p_pub_e,
  )
  // H1("Alice" || 0x02, N) & H1("Bob" || 0x02, N)
  assert_eq(
    @sm3.bytes_to_hex(@kgc.h1_scalar(b"Alice", @kgc.HID_KEYEX).to_be_bytes()),
    "a9ac0fda7380ed8e3325fddcd40a7221e3cd72f6ffa7f27d54ad494cedb4e212",
  )
  assert_eq(
    @sm3.bytes_to_hex(@kgc.h1_scalar(b"Bob", @kgc.HID_KEYEX).to_be_bytes()),
    "56af6ef1d2ab38f1ee77a5d538dd33b44917f2d9ad6ab68a993b36c727ed9838",
  )
  // de_A (128B raw)
  let de_a = match @kgc.extract_keyex_private_key(master, b"Alice") {
    Ok(k) => k
    Err(e) => abort("extract_keyex_private_key(Alice) failed: " + e)
  }
  let expected_de_a = "0fe8eab395199b56bf1d75bd2cd610b6424f08d1092922c5882b52dcd6ca832a" +
    "7da57bc50241f9e5bfddc075dd9d32c7777100d736916cfc165d8d36e0634cd7" +
    "83a457daf52cad464c903b26062caf937bb40e37daded9eda401050e49c8ad0c" +
    "6970876b9aad1b7a50bb4863a11e574af1fe3c5975161d73de4c3af621fb1efb"
  assert_eq(@sm3.bytes_to_hex(de_a.to_bytes_raw()), expected_de_a)
  // de_B (128B raw)
  let de_b = match @kgc.extract_keyex_private_key(master, b"Bob") {
    Ok(k) => k
    Err(e) => abort("extract_keyex_private_key(Bob) failed: " + e)
  }
  let expected_de_b = "74ccc3ac9c383c60af083972b96d05c75f12c8907d128a17adafbab8c5a4acf7" +
    "01092ff4de89362670c21711b6dbe52dcd5f8e40c6654b3dece573c2ab3d29b2" +
    "44b0294aa04290e1524ff3e3da8cfd432bb64de3a8040b5b88d1b5fc86a4ebc1" +
    "8cfc48fb4ff37f1e27727464f3c34e2153861ad08e972d1625fc1a7bd18d5539"
  assert_eq(@sm3.bytes_to_hex(de_b.to_bytes_raw()), expected_de_b)
  // Q_A and Q_B (64B raw)
  let q_a = @kgc.derive_enc_user_public_point(p_pub_e, b"Alice", @kgc.HID_KEYEX)
  assert_eq(
    @sm3.bytes_to_hex(q_a.to_bytes_raw()),
    "66c68126e6c3e19769a203c0c3275cf9121a4a116d7851da9a702a3e14f679dd" +
    "52af31f245eb74cde62f99a2b557b6219c53c3f3ba7b21e1fdc62ea4bcff9795",
  )
  let q_b = @kgc.derive_enc_user_public_point(p_pub_e, b"Bob", @kgc.HID_KEYEX)
  assert_eq(
    @sm3.bytes_to_hex(q_b.to_bytes_raw()),
    "a1c5ea63ae85302b026c2ee86dc7e8802ce3083061571fc98747011ce088bbd7" +
    "635385a8f01c8e73720ca4ad5de8125810b6271c84b27ec6eab182c6266e4da2",
  )
  // Pairing consistency: e(de_A, Q_A) == e(de_B, Q_B) == e(P2, P_pub-e)
  let g = p_pub_e.precompute_g()
  assert_eq(@kgc.pair(de_a.to_g2(), q_a), g)
  assert_eq(@kgc.pair(de_b.to_g2(), q_b), g)
}

///|
test "GB/T 38635.4 (Part 4) official KGC vectors: P_pub-e, de_B, Q_B, g" {
  let ke_hex = "0001edee3778f441f8dea3d9fa0acc4e07ee36c93f9a08618af4ad85cede1c22"
  let master = match
    @kgc.EncMasterPrivateKey::from_bytes_strict(must_hex(ke_hex)) {
    Some(k) => k
    None => abort("valid Part 4 ke rejected")
  }
  let p_pub_e = master.public_key()
  assert_eq(
    @sm3.bytes_to_hex(p_pub_e.to_bytes_raw()),
    "787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff" +
    "769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1",
  )
  // H1("Bob" || 0x03, N)
  assert_eq(
    @sm3.bytes_to_hex(@kgc.h1_scalar(b"Bob", @kgc.HID_ENC).to_be_bytes()),
    "9cb1f6288ce0e51043ce72344582ffc301e0a812a7f5f2004b85547a24b82716",
  )
  // de_B (128B raw)
  let de_b = match @kgc.extract_enc_private_key(master, b"Bob") {
    Ok(k) => k
    Err(e) => abort("extract_enc_private_key(Bob) failed: " + e)
  }
  let expected_de_b = "94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683" +
    "115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b158" +
    "7aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f" +
    "27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1"
  assert_eq(@sm3.bytes_to_hex(de_b.to_bytes_raw()), expected_de_b)
  assert_eq(
    @sm3.bytes_to_hex(de_b.to_bytes_uncompressed()),
    "04" + expected_de_b,
  )
  // Q_B = [H1("Bob" || 0x03, N)]P1 + P_pub-e (64B raw)
  let q_b = @kgc.derive_enc_user_public_point(p_pub_e, b"Bob", @kgc.HID_ENC)
  assert_eq(
    @sm3.bytes_to_hex(q_b.to_bytes_raw()),
    "709d165808b0a43e2574e203fa885abcbab16a240c4c1916552e7c43d09763b8" +
    "693269a6be2456f43333758274786b6051ff87b7f198da4ba1a2c6e336f51fcc",
  )
  // g = e(P2, P_pub-e) (384B)
  let g = p_pub_e.precompute_g()
  let expected_g = "9746fc5b231cedf36f835c47893d63c6ff652bcb92375ce3c2ab256d1fd56413" +
    "232a2f80cfbae061f196bb99213d50306648ac33cdc78e8f8a1563ffbf3bd3eb" +
    "68e8a16c0ac905f692904abcc004b1acf12106bd0a15b6e708d76e72b9288ef2" +
    "9436a60c403f4f8bac4dd3e393e25419e634fc2b3daf247f6092a802f60d5c58" +
    "a140eaef3893d574cb83c01d951a53f51975760be57f3bbd89817498d2158352" +
    "95a2bcce25359d033fc654bd6a9e462e5bd0686ff6ddd7455f71fff15affd3f0" +
    "b04320190b1e90cedf6ac570147a23ae6f0eae45034e6c62124dd6e8978f78ad" +
    "a504e3b43c1dd36794217fa1b05ac046c4131854c3d3e3a5b5967a64a861f0a2" +
    "897f7b35d1c0e21d84d75cffac08c73e744a16a47ee76e28a0b03849888d10ff" +
    "24443bb424b12c41eaf6d34d925205901f5cba59cfeba35224660db3848b0bf5" +
    "0825403fb3f681ab2b036dbba25483d5cb98bd56f3df95f0a7a705a2f6fd804b" +
    "9ce7bc68062182cf5d9f4a98c5a4ed1f3b4ce4ea817d19ed7ef2ce98e6f5864d"
  assert_eq(@sm3.bytes_to_hex(g.to_bytes()), expected_g)
  assert_eq(@kgc.pair(de_b.to_g2(), q_b), g)
}

///|
test "t1 == 0 edge case returns Err and pair handles infinity" {
  // Sign master key ks = N - H1("Alice" || 0x01, N) => t1 = 0
  let h1_sign = @kgc.h1_scalar(b"Alice", @kgc.HID_SIGN)
  let bad_ks = h1_sign.neg()
  let bad_sign_master = match @kgc.SignMasterPrivateKey::from_fn(bad_ks) {
    Some(k) => k
    None => abort("negated non-zero H1 should be non-zero")
  }
  assert_true(
    @kgc.extract_sign_private_key(bad_sign_master, b"Alice") is Err(_),
  )
  // Different identity or hid with same master key succeeds
  assert_true(@kgc.extract_sign_private_key(bad_sign_master, b"Bob") is Ok(_))
  assert_true(
    @kgc.extract_sign_private_key(bad_sign_master, b"Alice", hid=b'\x04')
    is Ok(_),
  )
  // User public point [h1]P2 + [N - h1]P2 == O, and pair(O, P1) == 1
  let bad_p_pub_s = bad_sign_master.public_key()
  let inf_g2 = @kgc.derive_sign_user_public_point(bad_p_pub_s, b"Alice")
  assert_true(inf_g2.is_infinity())
  assert_eq(@kgc.pair(inf_g2, @ec.G1Affine::generator()), @field.Fp12::one())
  // KeyEx master key ke = N - H1("Bob" || 0x02, N) => t1 = 0
  let h1_keyex = @kgc.h1_scalar(b"Bob", @kgc.HID_KEYEX)
  let bad_keyex_master = match
    @kgc.EncMasterPrivateKey::from_fn(h1_keyex.neg()) {
    Some(k) => k
    None => abort("negated H1 should be non-zero")
  }
  assert_true(
    @kgc.extract_keyex_private_key(bad_keyex_master, b"Bob") is Err(_),
  )
  assert_true(@kgc.extract_enc_private_key(bad_keyex_master, b"Bob") is Ok(_))
  // Enc master key ke = N - H1("Bob" || 0x03, N) => t1 = 0
  let h1_enc = @kgc.h1_scalar(b"Bob", @kgc.HID_ENC)
  let bad_enc_master = match @kgc.EncMasterPrivateKey::from_fn(h1_enc.neg()) {
    Some(k) => k
    None => abort("negated H1 should be non-zero")
  }
  assert_true(@kgc.extract_enc_private_key(bad_enc_master, b"Bob") is Err(_))
  assert_true(@kgc.extract_keyex_private_key(bad_enc_master, b"Bob") is Ok(_))
  let inf_g1 = @kgc.derive_enc_user_public_point(
    bad_enc_master.public_key(),
    b"Bob",
    @kgc.HID_ENC,
  )
  assert_true(inf_g1.is_infinity())
  assert_eq(@kgc.pair(@ec.G2Affine::generator(), inf_g1), @field.Fp12::one())
  assert_eq(@kgc.pair(inf_g2, inf_g1), @field.Fp12::one())
}

///|
test "Master private keys reject 0, >= N, and wrong lengths; accept [1, N-1]" {
  let zero_32 = Bytes::make(32, b'\x00')
  let order_n_be = @field.order_n.to_be_bytes()
  let n_plus_1 = must_hex(
    "b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf26",
  )
  let n_minus_1 = must_hex(
    "b640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf24",
  )
  let one_32 = must_hex(
    "0000000000000000000000000000000000000000000000000000000000000001",
  )
  let all_ff = Bytes::make(32, b'\xff')
  // Reject 0, N, N+1, 0xff..ff, and wrong lengths
  assert_true(@kgc.SignMasterPrivateKey::from_bytes_strict(zero_32) is None)
  assert_true(@kgc.SignMasterPrivateKey::from_bytes_strict(order_n_be) is None)
  assert_true(@kgc.SignMasterPrivateKey::from_bytes_strict(n_plus_1) is None)
  assert_true(@kgc.SignMasterPrivateKey::from_bytes_strict(all_ff) is None)
  assert_true(
    @kgc.SignMasterPrivateKey::from_bytes_strict(Bytes::make(31, b'\x01'))
    is None,
  )
  assert_true(
    @kgc.SignMasterPrivateKey::from_bytes_strict(Bytes::make(33, b'\x01'))
    is None,
  )
  assert_true(@kgc.SignMasterPrivateKey::from_bytes_strict(b"") is None)
  assert_true(@kgc.SignMasterPrivateKey::from_fn(@field.Fn::zero()) is None)
  assert_true(@kgc.EncMasterPrivateKey::from_bytes_strict(zero_32) is None)
  assert_true(@kgc.EncMasterPrivateKey::from_bytes_strict(order_n_be) is None)
  assert_true(@kgc.EncMasterPrivateKey::from_bytes_strict(n_plus_1) is None)
  assert_true(@kgc.EncMasterPrivateKey::from_bytes_strict(all_ff) is None)
  assert_true(
    @kgc.EncMasterPrivateKey::from_bytes_strict(Bytes::make(31, b'\x01'))
    is None,
  )
  assert_true(
    @kgc.EncMasterPrivateKey::from_bytes_strict(Bytes::make(33, b'\x01'))
    is None,
  )
  assert_true(@kgc.EncMasterPrivateKey::from_bytes_strict(b"") is None)
  assert_true(@kgc.EncMasterPrivateKey::from_fn(@field.Fn::zero()) is None)
  // Accept boundary values 1 and N - 1
  match @kgc.SignMasterPrivateKey::from_bytes_strict(one_32) {
    Some(k) => {
      assert_eq(k.to_bytes(), one_32)
      assert_eq(k.public_key().to_g2(), @ec.G2Affine::generator())
    }
    None => abort("ks = 1 must be accepted")
  }
  match @kgc.SignMasterPrivateKey::from_bytes_strict(n_minus_1) {
    Some(k) => {
      assert_eq(k.to_bytes(), n_minus_1)
      assert_eq(k.public_key().to_g2(), @ec.G2Affine::generator().neg())
    }
    None => abort("ks = N - 1 must be accepted")
  }
  match @kgc.EncMasterPrivateKey::from_bytes_strict(one_32) {
    Some(k) => {
      assert_eq(k.to_bytes(), one_32)
      assert_eq(k.public_key().to_g1(), @ec.G1Affine::generator())
    }
    None => abort("ke = 1 must be accepted")
  }
  match @kgc.EncMasterPrivateKey::from_bytes_strict(n_minus_1) {
    Some(k) => {
      assert_eq(k.to_bytes(), n_minus_1)
      assert_eq(k.public_key().to_g1(), @ec.G1Affine::generator().neg())
    }
    None => abort("ke = N - 1 must be accepted")
  }
}

///|
test "Deterministic from_seed derivation and domain separation" {
  let s1 = @kgc.SignMasterPrivateKey::from_seed(b"master-seed-2026")
  let s1_again = @kgc.SignMasterPrivateKey::from_seed(b"master-seed-2026")
  let s2 = @kgc.SignMasterPrivateKey::from_seed(b"master-seed-2027")
  let s_empty = @kgc.SignMasterPrivateKey::from_seed(b"")
  assert_true(s1 == s1_again)
  assert_true(s1 != s2)
  assert_true(!s1.scalar().is_zero())
  assert_true(!s_empty.scalar().is_zero())
  let e1 = @kgc.EncMasterPrivateKey::from_seed(b"master-seed-2026")
  let e1_again = @kgc.EncMasterPrivateKey::from_seed(b"master-seed-2026")
  let e2 = @kgc.EncMasterPrivateKey::from_seed(b"master-seed-2027")
  let e_empty = @kgc.EncMasterPrivateKey::from_seed(b"")
  assert_true(e1 == e1_again)
  assert_true(e1 != e2)
  assert_true(!e1.scalar().is_zero())
  assert_true(!e_empty.scalar().is_zero())
  // Domain separation: same seed produces distinct sign vs enc master scalars
  assert_true(s1.to_bytes() != e1.to_bytes())
  // End-to-end extraction & pairing check with seed-derived keys
  let ds = match @kgc.extract_sign_private_key(s1, b"carol@example.com") {
    Ok(k) => k
    Err(e) => abort("sign extraction failed: " + e)
  }
  let p_pub_s = s1.public_key()
  let p_carol = @kgc.derive_sign_user_public_point(
    p_pub_s, b"carol@example.com",
  )
  assert_eq(@kgc.pair(p_carol, ds.to_g1()), p_pub_s.precompute_g())
  let de = match @kgc.extract_enc_private_key(e1, b"carol@example.com") {
    Ok(k) => k
    Err(e) => abort("enc extraction failed: " + e)
  }
  let p_pub_e = e1.public_key()
  let q_carol = @kgc.derive_enc_user_public_point(
    p_pub_e,
    b"carol@example.com",
    @kgc.HID_ENC,
  )
  assert_eq(@kgc.pair(de.to_g2(), q_carol), p_pub_e.precompute_g())
}

///|
test "Key encoding roundtrips and malformed point rejection (G1 and G2)" {
  let sign_master = @kgc.SignMasterPrivateKey::from_seed(b"roundtrip-sign")
  let p_pub_s = sign_master.public_key()
  let ds = match @kgc.extract_sign_private_key(sign_master, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let enc_master = @kgc.EncMasterPrivateKey::from_seed(b"roundtrip-enc")
  let p_pub_e = enc_master.public_key()
  let de = match @kgc.extract_enc_private_key(enc_master, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  // 1. Valid roundtrips: raw, uncompressed, from_g1 / from_g2
  match
    @kgc.SignMasterPublicKey::from_bytes_raw_strict(p_pub_s.to_bytes_raw()) {
    Some(k) => assert_true(k == p_pub_s)
    None => abort("SignMasterPublicKey raw roundtrip failed")
  }
  match
    @kgc.SignMasterPublicKey::from_bytes_uncompressed_strict(
      p_pub_s.to_bytes_uncompressed(),
    ) {
    Some(k) => assert_true(k == p_pub_s)
    None => abort("SignMasterPublicKey uncompressed roundtrip failed")
  }
  match @kgc.SignMasterPublicKey::from_g2(p_pub_s.to_g2()) {
    Some(k) => assert_true(k == p_pub_s)
    None => abort("SignMasterPublicKey from_g2 failed")
  }
  match @kgc.SignUserPrivateKey::from_bytes_raw_strict(ds.to_bytes_raw()) {
    Some(k) => assert_true(k == ds)
    None => abort("SignUserPrivateKey raw roundtrip failed")
  }
  match
    @kgc.SignUserPrivateKey::from_bytes_uncompressed_strict(
      ds.to_bytes_uncompressed(),
    ) {
    Some(k) => assert_true(k == ds)
    None => abort("SignUserPrivateKey uncompressed roundtrip failed")
  }
  match @kgc.SignUserPrivateKey::from_g1(ds.to_g1()) {
    Some(k) => assert_true(k == ds)
    None => abort("SignUserPrivateKey from_g1 failed")
  }
  match @kgc.EncMasterPublicKey::from_bytes_raw_strict(p_pub_e.to_bytes_raw()) {
    Some(k) => assert_true(k == p_pub_e)
    None => abort("EncMasterPublicKey raw roundtrip failed")
  }
  match
    @kgc.EncMasterPublicKey::from_bytes_uncompressed_strict(
      p_pub_e.to_bytes_uncompressed(),
    ) {
    Some(k) => assert_true(k == p_pub_e)
    None => abort("EncMasterPublicKey uncompressed roundtrip failed")
  }
  match @kgc.EncMasterPublicKey::from_g1(p_pub_e.to_g1()) {
    Some(k) => assert_true(k == p_pub_e)
    None => abort("EncMasterPublicKey from_g1 failed")
  }
  match @kgc.EncUserPrivateKey::from_bytes_raw_strict(de.to_bytes_raw()) {
    Some(k) => assert_true(k == de)
    None => abort("EncUserPrivateKey raw roundtrip failed")
  }
  match
    @kgc.EncUserPrivateKey::from_bytes_uncompressed_strict(
      de.to_bytes_uncompressed(),
    ) {
    Some(k) => assert_true(k == de)
    None => abort("EncUserPrivateKey uncompressed roundtrip failed")
  }
  match @kgc.EncUserPrivateKey::from_g2(de.to_g2()) {
    Some(k) => assert_true(k == de)
    None => abort("EncUserPrivateKey from_g2 failed")
  }
  // 2. Infinity rejection
  assert_true(
    @kgc.SignMasterPublicKey::from_g2(@ec.G2Affine::identity()) is None,
  )
  assert_true(@kgc.EncUserPrivateKey::from_g2(@ec.G2Affine::identity()) is None)
  assert_true(
    @kgc.SignUserPrivateKey::from_g1(@ec.G1Affine::identity()) is None,
  )
  assert_true(
    @kgc.EncMasterPublicKey::from_g1(@ec.G1Affine::identity()) is None,
  )
  let zero_64 = Bytes::make(64, b'\x00')
  let zero_65 = Bytes::makei(65, fn(i) {
    if i == 0 {
      b'\x04'
    } else {
      b'\x00'
    }
  })
  let zero_128 = Bytes::make(128, b'\x00')
  let zero_129 = Bytes::makei(129, fn(i) {
    if i == 0 {
      b'\x04'
    } else {
      b'\x00'
    }
  })
  assert_true(@kgc.SignUserPrivateKey::from_bytes_raw_strict(zero_64) is None)
  assert_true(
    @kgc.SignUserPrivateKey::from_bytes_uncompressed_strict(zero_65) is None,
  )
  assert_true(@kgc.EncMasterPublicKey::from_bytes_raw_strict(zero_64) is None)
  assert_true(
    @kgc.EncMasterPublicKey::from_bytes_uncompressed_strict(zero_65) is None,
  )
  assert_true(@kgc.SignMasterPublicKey::from_bytes_raw_strict(zero_128) is None)
  assert_true(
    @kgc.SignMasterPublicKey::from_bytes_uncompressed_strict(zero_129) is None,
  )
  assert_true(@kgc.EncUserPrivateKey::from_bytes_raw_strict(zero_128) is None)
  assert_true(
    @kgc.EncUserPrivateKey::from_bytes_uncompressed_strict(zero_129) is None,
  )
  // 3. Wrong prefixes and lengths
  let bad_g1_prefix = Bytes::makei(65, fn(i) {
    if i == 0 {
      b'\x02'
    } else {
      ds.to_bytes_raw()[i - 1]
    }
  })
  assert_true(
    @kgc.SignUserPrivateKey::from_bytes_uncompressed_strict(bad_g1_prefix)
    is None,
  )
  assert_true(
    @kgc.EncMasterPublicKey::from_bytes_uncompressed_strict(bad_g1_prefix)
    is None,
  )
  assert_true(
    @kgc.SignUserPrivateKey::from_bytes_raw_strict(Bytes::make(63, b'\x01'))
    is None,
  )
  assert_true(
    @kgc.EncMasterPublicKey::from_bytes_raw_strict(Bytes::make(65, b'\x01'))
    is None,
  )
  let bad_g2_prefix = Bytes::makei(129, fn(i) {
    if i == 0 {
      b'\x03'
    } else {
      p_pub_s.to_bytes_raw()[i - 1]
    }
  })
  assert_true(
    @kgc.SignMasterPublicKey::from_bytes_uncompressed_strict(bad_g2_prefix)
    is None,
  )
  assert_true(
    @kgc.EncUserPrivateKey::from_bytes_uncompressed_strict(bad_g2_prefix)
    is None,
  )
  assert_true(
    @kgc.SignMasterPublicKey::from_bytes_raw_strict(Bytes::make(127, b'\x01'))
    is None,
  )
  assert_true(
    @kgc.EncUserPrivateKey::from_bytes_raw_strict(Bytes::make(129, b'\x01'))
    is None,
  )
  // 4. Off-curve G1 (flip last bit of y) and coordinate >= p
  let ds_raw = ds.to_bytes_raw()
  let off_curve_g1 = Bytes::makei(64, fn(i) {
    if i == 63 {
      (ds_raw[63].to_int() ^ 1).to_byte()
    } else {
      ds_raw[i]
    }
  })
  assert_true(
    @kgc.SignUserPrivateKey::from_bytes_raw_strict(off_curve_g1) is None,
  )
  assert_true(
    @kgc.EncMasterPublicKey::from_bytes_raw_strict(off_curve_g1) is None,
  )
  let p_bytes = @field.modulus_p.to_be_bytes()
  let g1_ge_p = Bytes::makei(64, fn(i) {
    if i < 32 {
      p_bytes[i]
    } else {
      ds_raw[i]
    }
  })
  assert_true(@kgc.SignUserPrivateKey::from_bytes_raw_strict(g1_ge_p) is None)
  assert_true(@kgc.EncMasterPublicKey::from_bytes_raw_strict(g1_ge_p) is None)
  // 5. Off-curve G2, wrong-twist G2 (y^2 = x^3 + 5/u), and cofactor G2 (on E'(Fp2) but not in G2 subgroup)
  let ps_raw = p_pub_s.to_bytes_raw()
  let off_curve_g2 = Bytes::makei(128, fn(i) {
    if i == 127 {
      (ps_raw[127].to_int() ^ 1).to_byte()
    } else {
      ps_raw[i]
    }
  })
  assert_true(
    @kgc.SignMasterPublicKey::from_bytes_raw_strict(off_curve_g2) is None,
  )
  assert_true(
    @kgc.EncUserPrivateKey::from_bytes_raw_strict(off_curve_g2) is None,
  )
  let wrong_twist_g2 = must_hex(
    "0000000000000000000000000000000000000000000000000000000000000001" +
    "0000000000000000000000000000000000000000000000000000000000000002" +
    "64430ad9bb77e6a1e74108282f7a6631946a0764171c1e7e41cabcd2844c125f" +
    "718da4efb433867d47e25eeb9706c91c429177370bc52c19e72086bc07d630be",
  )
  assert_true(
    @kgc.SignMasterPublicKey::from_bytes_raw_strict(wrong_twist_g2) is None,
  )
  assert_true(
    @kgc.EncUserPrivateKey::from_bytes_raw_strict(wrong_twist_g2) is None,
  )
  let cofactor_g2 = must_hex(
    "0000000000000000000000000000000000000000000000000000000000000001" +
    "0000000000000000000000000000000000000000000000000000000000000001" +
    "9324098b67dd1ccfb2bc8054215aaf13516d207bd61c4b8b3876c76edf7aa9ec" +
    "9782d17c0113ff75963b71b2afb4eb089a6c6ac94e599b48be78baaf3a5d5f96",
  )
  let cofactor_g2_unc = Bytes::makei(129, fn(i) {
    if i == 0 {
      b'\x04'
    } else {
      cofactor_g2[i - 1]
    }
  })
  assert_true(
    @kgc.SignMasterPublicKey::from_bytes_raw_strict(cofactor_g2) is None,
  )
  assert_true(
    @kgc.SignMasterPublicKey::from_bytes_uncompressed_strict(cofactor_g2_unc)
    is None,
  )
  assert_true(
    @kgc.EncUserPrivateKey::from_bytes_raw_strict(cofactor_g2) is None,
  )
  assert_true(
    @kgc.EncUserPrivateKey::from_bytes_uncompressed_strict(cofactor_g2_unc)
    is None,
  )
}
