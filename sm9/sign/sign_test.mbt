///|
fn must_hex(hex : String) -> Bytes {
  match @sm3.hex_to_bytes(hex) {
    Some(b) => b
    None => abort("invalid hex in test")
  }
}

///|
fn must_fn(hex : String) -> @field.Fn {
  match @field.Fn::from_be_bytes_strict(must_hex(hex)) {
    Some(x) => x
    None => abort("invalid Fn hex in test")
  }
}

///|
fn must_g1_raw(hex : String) -> @ec.G1Affine {
  match @ec.G1Affine::from_bytes_raw_strict(must_hex(hex)) {
    Some(p) => p
    None => abort("invalid G1Affine hex in test")
  }
}

///|
fn must_g2_raw(hex : String) -> @ec.G2Affine {
  match @ec.G2Affine::from_bytes_raw_strict(must_hex(hex)) {
    Some(p) => p
    None => abort("invalid G2Affine hex in test")
  }
}

///|
/// Official GB/T 38635.2 Appendix A master signing public key `P_pub-s` (128B raw).
fn official_p_pub_s() -> @ec.G2Affine {
  must_g2_raw(
    "9f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c408" +
    "29dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e32" +
    "69850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c25" +
    "41e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d",
  )
}

///|
/// Official GB/T 38635.2 Appendix A Alice signing private key `ds_A` (64B raw).
fn official_ds_a() -> @ec.G1Affine {
  must_g1_raw(
    "a5702f05cf1315305e2d6eb64b0deb923db1a0bcf0caff90523ac8754aa69820" +
    "78559a844411f9825c109f5ee3f52d720dd01785392a727bb1556952b2b013d3",
  )
}

///|
fn flip_bit(src : Bytes, byte_idx : Int32, bit_mask : Byte) -> Bytes {
  Bytes::makei(src.length(), fn(i) {
    if i == byte_idx {
      (src[i].to_int() ^ bit_mask.to_int()).to_byte()
    } else {
      src[i]
    }
  })
}

///|
test "GB/T 38635.2 Appendix A official SM9 signature test vector (byte-exact)" {
  let id_a = b"Alice"
  let msg = b"Chinese IBS standard"
  let p_pub_s = official_p_pub_s()
  let ds_a = official_ds_a()
  let r = must_fn(
    "00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe",
  )
  // Verify precomputed g = e(P_pub-s, P1) matches Appendix A byte-for-byte
  let g = @sign.precompute_g(p_pub_s)
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
  // Verify w = g^r matches Appendix A byte-for-byte
  let w = g.cyclotomic_pow_u256(r.to_u256())
  let expected_w = "81377b8fdbc2839b4fa2d0e0f8aa6853bbbe9e9c4099608f8612c6078acd7563" +
    "815aeba217ad502da0f48704cc73cabb3c06209bd87142e14cbd99e8bca1680f" +
    "30dadc5cd9e207aee32209f6c3ca3ec0d800a1a42d33c73153ded47c70a39d2e" +
    "8eaf5d179a1836b359a9d1d9bfc19f2efcdb829328620962bd3fdf15f2567f58" +
    "a543d25609ae943920679194ed30328bb33fd15660bde485c6b79a7b32b01398" +
    "3f012db04ba59fe88db889321cc2373d4c0c35e84f7ab1ff33679bca575d6765" +
    "4f8624eb435b838cca77b2d0347e65d5e46964412a096f4150d8c5ede5440ddf" +
    "0656fcb663d24731e80292188a2471b8b68aa993899268499d23c89755a1a897" +
    "44643cead40f0965f28e1cd2895c3d118e4f65c9a0e3e741b6dd52c0ee2d25f5" +
    "898d60848026b7efb8fcc1b2442ecf0795f8a81cee99a6248f294c82c90d26bd" +
    "6a814aaf475f128aef43a128e37f80154ae6cb92cad7d1501bae30f750b3a9bd" +
    "1f96b08e97997363911314705bfb9a9dbb97f75553ec90fbb2ddae53c8f68e42"
  assert_eq(@sm3.bytes_to_hex(w.to_bytes()), expected_w)
  // Sign with official r
  let sig = match @sign.sign_with_r(p_pub_s, ds_a, msg, r) {
    Ok(s) => s
    Err(e) => abort("sign_with_r failed: " + e)
  }
  let expected_h = "823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb"
  let expected_s = "73bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c" +
    "856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05"
  assert_eq(@sm3.bytes_to_hex(sig.h().to_be_bytes()), expected_h)
  assert_eq(@sm3.bytes_to_hex(sig.s().to_bytes_raw()), expected_s)
  // Precomputed signing must yield exact same signature
  let sig_pre = match @sign.sign_with_r_precomputed(g, ds_a, msg, r) {
    Ok(s) => s
    Err(e) => abort("sign_with_r_precomputed failed: " + e)
  }
  assert_eq(sig_pre, sig)
  // Both verify and verify_precomputed must accept
  assert_true(@sign.verify(p_pub_s, id_a, msg, sig))
  assert_true(@sign.verify_precomputed(p_pub_s, g, id_a, msg, sig))
}

///|
test "Deterministic signing roundtrip, entropy uniqueness, and domain separation" {
  let id_a = b"Alice"
  let p_pub_s = official_p_pub_s()
  let ds_a = official_ds_a()
  let msg = b"Deterministic SM9 signature test payload"
  let sig1 = match @sign.sign_deterministic(p_pub_s, ds_a, msg, b"") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  let sig1_repeat = match @sign.sign_deterministic(p_pub_s, ds_a, msg, b"") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  let sig2 = match @sign.sign_deterministic(p_pub_s, ds_a, msg, b"entropy-A") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  let sig3 = match @sign.sign_deterministic(p_pub_s, ds_a, msg, b"entropy-B") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  assert_eq(sig1, sig1_repeat)
  assert_true(sig1 != sig2)
  assert_true(sig2 != sig3)
  assert_true(sig1 != sig3)
  assert_true(@sign.verify(p_pub_s, id_a, msg, sig1))
  assert_true(@sign.verify(p_pub_s, id_a, msg, sig2))
  assert_true(@sign.verify(p_pub_s, id_a, msg, sig3))
  // Empty message and multi-block message
  let sig_empty = match @sign.sign_deterministic(p_pub_s, ds_a, b"", b"empty") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  assert_true(@sign.verify(p_pub_s, id_a, b"", sig_empty))
  let long_msg = Bytes::makei(200, fn(i) { (i & 0xFF).to_byte() })
  let sig_long = match
    @sign.sign_deterministic(p_pub_s, ds_a, long_msg, b"long") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  assert_true(@sign.verify(p_pub_s, id_a, long_msg, sig_long))
  // Length-prefix domain separation: ("ab", "c") vs ("a", "bc")
  let sig_ab_c = match @sign.sign_deterministic(p_pub_s, ds_a, b"ab", b"c") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  let sig_a_bc = match @sign.sign_deterministic(p_pub_s, ds_a, b"a", b"bc") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  assert_true(sig_ab_c != sig_a_bc)
  assert_true(@sign.verify(p_pub_s, id_a, b"ab", sig_ab_c))
  assert_true(!@sign.verify(p_pub_s, id_a, b"a", sig_ab_c))
  assert_true(@sign.verify(p_pub_s, id_a, b"a", sig_a_bc))
  assert_true(!@sign.verify(p_pub_s, id_a, b"ab", sig_a_bc))
}

///|
test "Custom hid key derivation and verification roundtrip" {
  let ks = must_fn(
    "000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4",
  )
  let p_pub_s = official_p_pub_s()
  let id_b = b"Bob"
  let custom_hid : Byte = b'\x09'
  // Derive Bob's signing key for custom hid = 0x09 directly from ks
  let z = Bytes::makei(id_b.length() + 1, fn(i) {
    if i < id_b.length() {
      id_b[i]
    } else {
      custom_hid
    }
  })
  let h1 = match
    @field.Fn::from_be_bytes_nonzero(@sm3.h1(z, @field.order_n.to_be_bytes())) {
    Some(x) => x
    None => abort("invalid h1")
  }
  let t1 = h1.add(ks)
  let t2 = match t1.inv() {
    Some(inv) => ks.mul(inv)
    None => abort("unexpected zero t1")
  }
  let ds_b = @ec.G1Affine::generator().scalar_mul_fn(t2).to_affine()
  let msg = b"custom hid test"
  let sig = match @sign.sign_deterministic(p_pub_s, ds_b, msg, b"hid9") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  assert_true(@sign.verify(p_pub_s, id_b, msg, sig, hid=custom_hid))
  assert_true(!@sign.verify(p_pub_s, id_b, msg, sig))
}

///|
test "Signature 96B raw and 97B uncompressed encoding/decoding roundtrip" {
  let p_pub_s = official_p_pub_s()
  let ds_a = official_ds_a()
  let r = must_fn(
    "00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe",
  )
  let sig = match @sign.sign_with_r(p_pub_s, ds_a, b"Chinese IBS standard", r) {
    Ok(s) => s
    Err(e) => abort(e)
  }
  // 96B raw format
  let raw = sig.to_bytes_raw()
  assert_eq(raw.length(), 96)
  match @sign.Signature::from_bytes_raw_strict(raw) {
    Some(decoded) => assert_eq(decoded, sig)
    None => abort("from_bytes_raw_strict failed on valid raw signature")
  }
  // 97B uncompressed format (h || 0x04 || x_S || y_S)
  let unc = sig.to_bytes_uncompressed()
  assert_eq(unc.length(), 97)
  assert_eq(unc[32], b'\x04')
  match @sign.Signature::from_bytes_uncompressed_strict(unc) {
    Some(decoded) => assert_eq(decoded, sig)
    None =>
      abort("from_bytes_uncompressed_strict failed on valid uncompressed sig")
  }
  // Reject wrong lengths
  assert_true(@sign.Signature::from_bytes_raw_strict(raw[0:95]) is None)
  assert_true(@sign.Signature::from_bytes_raw_strict(unc) is None)
  assert_true(@sign.Signature::from_bytes_uncompressed_strict(raw) is None)
  let unc_98 = Bytes::makei(98, fn(i) { if i < 97 { unc[i] } else { b'\x00' } })
  assert_true(@sign.Signature::from_bytes_uncompressed_strict(unc_98) is None)
  // Reject bad uncompressed point prefix (not 0x04)
  let bad_prefix = Bytes::makei(97, fn(i) {
    if i == 32 {
      b'\x02'
    } else {
      unc[i]
    }
  })
  assert_true(
    @sign.Signature::from_bytes_uncompressed_strict(bad_prefix) is None,
  )
}

///|
test "Adversarial forgery and malformed signature rejection" {
  let id_a = b"Alice"
  let msg = b"Chinese IBS standard"
  let p_pub_s = official_p_pub_s()
  let ds_a = official_ds_a()
  let g = @sign.precompute_g(p_pub_s)
  let r = must_fn(
    "00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe",
  )
  let sig = match @sign.sign_with_r(p_pub_s, ds_a, msg, r) {
    Ok(s) => s
    Err(e) => abort(e)
  }
  // 1. Flip 1 bit in message
  let msg_flipped = flip_bit(msg, 0, b'\x01')
  assert_true(!@sign.verify(p_pub_s, id_a, msg_flipped, sig))
  let msg_flipped_end = flip_bit(msg, msg.length() - 1, b'\x80')
  assert_true(!@sign.verify(p_pub_s, id_a, msg_flipped_end, sig))
  assert_true(!@sign.verify(p_pub_s, id_a, b"Chinese IBS standard ", sig))
  assert_true(!@sign.verify(p_pub_s, id_a, b"", sig))
  // 2. Wrong identity
  assert_true(!@sign.verify(p_pub_s, b"Bob", msg, sig))
  assert_true(!@sign.verify(p_pub_s, b"alice", msg, sig))
  assert_true(!@sign.verify(p_pub_s, b"Alice\x00", msg, sig))
  assert_true(!@sign.verify(p_pub_s, b"", msg, sig))
  // 3. Wrong hid
  assert_true(!@sign.verify(p_pub_s, id_a, msg, sig, hid=b'\x02'))
  assert_true(!@sign.verify(p_pub_s, id_a, msg, sig, hid=b'\x03'))
  assert_true(!@sign.verify(p_pub_s, id_a, msg, sig, hid=b'\x00'))
  // 4. Flip 1 bit in h
  let h_flipped_bytes = flip_bit(sig.h().to_be_bytes(), 31, b'\x01')
  let h_flipped = match @field.Fn::from_be_bytes_nonzero(h_flipped_bytes) {
    Some(x) => x
    None => abort("unexpected invalid h_flipped")
  }
  let sig_bad_h = match @sign.Signature::new_checked(h_flipped, sig.s()) {
    Some(s) => s
    None => abort("unexpected invalid sig_bad_h")
  }
  assert_true(!@sign.verify(p_pub_s, id_a, msg, sig_bad_h))
  // 5. Tamper S with another valid G1 point (-S and S + P1)
  let sig_neg_s = match @sign.Signature::new_checked(sig.h(), sig.s().neg()) {
    Some(s) => s
    None => abort("unexpected invalid sig_neg_s")
  }
  assert_true(!@sign.verify(p_pub_s, id_a, msg, sig_neg_s))
  let s_plus_p1 = sig
    .s()
    .to_jac()
    .add_mixed(@ec.G1Affine::generator())
    .to_affine()
  let sig_other_s = match @sign.Signature::new_checked(sig.h(), s_plus_p1) {
    Some(s) => s
    None => abort("unexpected invalid sig_other_s")
  }
  assert_true(!@sign.verify(p_pub_s, id_a, msg, sig_other_s))
  // 6. All-zero h rejected
  assert_true(@sign.Signature::new_checked(@field.Fn::zero(), sig.s()) is None)
  let raw = sig.to_bytes_raw()
  let raw_zero_h = Bytes::makei(96, fn(i) {
    if i < 32 {
      b'\x00'
    } else {
      raw[i]
    }
  })
  assert_true(@sign.Signature::from_bytes_raw_strict(raw_zero_h) is None)
  let unc = sig.to_bytes_uncompressed()
  let unc_zero_h = Bytes::makei(97, fn(i) {
    if i < 32 {
      b'\x00'
    } else {
      unc[i]
    }
  })
  assert_true(
    @sign.Signature::from_bytes_uncompressed_strict(unc_zero_h) is None,
  )
  // 7. h >= N rejected (h == N and h == 0xFF..FF)
  let n_bytes = @field.order_n.to_be_bytes()
  let raw_h_eq_n = Bytes::makei(96, fn(i) {
    if i < 32 {
      n_bytes[i]
    } else {
      raw[i]
    }
  })
  assert_true(@sign.Signature::from_bytes_raw_strict(raw_h_eq_n) is None)
  let raw_h_max = Bytes::makei(96, fn(i) {
    if i < 32 {
      b'\xff'
    } else {
      raw[i]
    }
  })
  assert_true(@sign.Signature::from_bytes_raw_strict(raw_h_max) is None)
  let unc_h_eq_n = Bytes::makei(97, fn(i) {
    if i < 32 {
      n_bytes[i]
    } else {
      unc[i]
    }
  })
  assert_true(
    @sign.Signature::from_bytes_uncompressed_strict(unc_h_eq_n) is None,
  )
  // 8. S = infinity and off-curve S rejected
  assert_true(
    @sign.Signature::new_checked(sig.h(), @ec.G1Affine::identity()) is None,
  )
  let raw_inf_s = Bytes::makei(96, fn(i) {
    if i < 32 {
      raw[i]
    } else {
      b'\x00'
    }
  })
  assert_true(@sign.Signature::from_bytes_raw_strict(raw_inf_s) is None)
  let raw_off_curve = flip_bit(raw, 95, b'\x01')
  assert_true(@sign.Signature::from_bytes_raw_strict(raw_off_curve) is None)
  let unc_off_curve = flip_bit(unc, 96, b'\x01')
  assert_true(
    @sign.Signature::from_bytes_uncompressed_strict(unc_off_curve) is None,
  )
  // 9. Verify with different master public key P_pub-s
  let other_p_pub_s = @ec.G2Affine::generator()
    .scalar_mul_fn(@field.Fn::from_u64(42UL))
    .to_affine()
  assert_true(!@sign.verify(other_p_pub_s, id_a, msg, sig))
  // 10. Verify with infinity P_pub-s or bad precomputed g
  assert_true(!@sign.verify(@ec.G2Affine::identity(), id_a, msg, sig))
  assert_true(
    !@sign.verify_precomputed(@ec.G2Affine::identity(), g, id_a, msg, sig),
  )
  assert_true(
    !@sign.verify_precomputed(p_pub_s, @field.Fp12::zero(), id_a, msg, sig),
  )
  assert_true(
    !@sign.verify_precomputed(p_pub_s, @field.Fp12::one(), id_a, msg, sig),
  )
  let wrong_g = @sign.precompute_g(other_p_pub_s)
  assert_true(!@sign.verify_precomputed(p_pub_s, wrong_g, id_a, msg, sig))
}

///|
test "Error paths for invalid inputs to signing functions" {
  let p_pub_s = official_p_pub_s()
  let ds_a = official_ds_a()
  let g = @sign.precompute_g(p_pub_s)
  let r = @field.Fn::from_u64(7UL)
  let msg = b"hello"
  assert_true(
    @sign.sign_with_r(@ec.G2Affine::identity(), ds_a, msg, r) is Err(_),
  )
  assert_true(
    @sign.sign_with_r(p_pub_s, @ec.G1Affine::identity(), msg, r) is Err(_),
  )
  assert_true(
    @sign.sign_with_r(p_pub_s, ds_a, msg, @field.Fn::zero()) is Err(_),
  )
  assert_true(
    @sign.sign_with_r_precomputed(@field.Fp12::zero(), ds_a, msg, r) is Err(_),
  )
  assert_true(
    @sign.sign_with_r_precomputed(@field.Fp12::one(), ds_a, msg, r) is Err(_),
  )
  assert_true(
    @sign.sign_with_r_precomputed(g, @ec.G1Affine::identity(), msg, r) is Err(_),
  )
  assert_true(
    @sign.sign_with_r_precomputed(g, ds_a, msg, @field.Fn::zero()) is Err(_),
  )
  assert_true(
    @sign.sign_deterministic(@ec.G2Affine::identity(), ds_a, msg, b"") is Err(_),
  )
  assert_true(
    @sign.sign_deterministic(p_pub_s, @ec.G1Affine::identity(), msg, b"")
    is Err(_),
  )
}

///|
test "Adversarial: reject -1 and non-cyclotomic Fp12 elements as precomputed g" {
  let id_a = b"Alice"
  let msg = b"Chinese IBS standard"
  let p_pub_s = official_p_pub_s()
  let ds_a = official_ds_a()
  let g = @sign.precompute_g(p_pub_s)
  let r = must_fn(
    "00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe",
  )
  let sig = match @sign.sign_with_r(p_pub_s, ds_a, msg, r) {
    Ok(s) => s
    Err(e) => abort(e)
  }
  // -1 lies in the unitary subgroup (g * conj(g) == 1) but NOT in G_{Phi_6}(Fp2)
  let neg_one = @field.Fp12::one().neg()
  // General non-cyclotomic elements in Fp12
  let two = @field.Fp12::one().add(@field.Fp12::one())
  let non_cyclotomic = @field.Fp12::new(
    @field.Fp6::from_fp2(@field.Fp2::from_fp(@field.Fp::from_u64(3UL))),
    @field.Fp6::one(),
  )
  let perturbed_g = g.add(@field.Fp12::one())

  assert_true(@sign.sign_with_r_precomputed(neg_one, ds_a, msg, r) is Err(_))
  assert_true(@sign.sign_with_r_precomputed(two, ds_a, msg, r) is Err(_))
  assert_true(
    @sign.sign_with_r_precomputed(non_cyclotomic, ds_a, msg, r) is Err(_),
  )
  assert_true(
    @sign.sign_with_r_precomputed(perturbed_g, ds_a, msg, r) is Err(_),
  )

  assert_true(!@sign.verify_precomputed(p_pub_s, neg_one, id_a, msg, sig))
  assert_true(!@sign.verify_precomputed(p_pub_s, two, id_a, msg, sig))
  assert_true(
    !@sign.verify_precomputed(p_pub_s, non_cyclotomic, id_a, msg, sig),
  )
  assert_true(!@sign.verify_precomputed(p_pub_s, perturbed_g, id_a, msg, sig))
}
