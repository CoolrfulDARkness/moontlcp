///|
fn must_hex(hex : String) -> Bytes {
  match @sm3.hex_to_bytes(hex) {
    Some(b) => b
    None => abort("invalid test hex literal")
  }
}

///|
fn must_fn(hex : String) -> @field.Fn {
  match @field.Fn::from_be_bytes_nonzero(must_hex(hex)) {
    Some(v) => v
    None => abort("invalid non-zero Fn scalar hex")
  }
}

///|
fn must_g1_raw(hex : String) -> @ec.G1Affine {
  match @ec.G1Affine::from_bytes_raw_strict(must_hex(hex)) {
    Some(pt) => pt
    None => abort("invalid G1 raw point hex")
  }
}

///|
fn must_g2_raw(hex : String) -> @ec.G2Affine {
  match @ec.G2Affine::from_bytes_raw_strict(must_hex(hex)) {
    Some(pt) => pt
    None => abort("invalid G2 raw point hex")
  }
}

///|
fn flip_byte(src : Bytes, idx : Int32) -> Bytes {
  Bytes::makei(src.length(), fn(i) {
    if i == idx {
      (src[i].to_int() ^ 0x01).to_byte()
    } else {
      src[i]
    }
  })
}

///|
/// Shared GB/T 38635.3 Appendix A test fixture (master public key, user private keys, ephemerals).
fn official_fixture() -> (
  @ec.G1Affine,
  @ec.G2Affine,
  @ec.G2Affine,
  @field.Fn,
  @field.Fn,
) {
  let p_pub_e = must_g1_raw(
    "9174542668e8f14ab273c0945c3690c66e5dd09678b86f734c4350567ed06283" +
    "54e598c6bf749a3dacc9fffedd9db6866c50457cfc7aa2a4ad65c3168ff74210",
  )
  let de_a = must_g2_raw(
    "0fe8eab395199b56bf1d75bd2cd610b6424f08d1092922c5882b52dcd6ca832a" +
    "7da57bc50241f9e5bfddc075dd9d32c7777100d736916cfc165d8d36e0634cd7" +
    "83a457daf52cad464c903b26062caf937bb40e37daded9eda401050e49c8ad0c" +
    "6970876b9aad1b7a50bb4863a11e574af1fe3c5975161d73de4c3af621fb1efb",
  )
  let de_b = must_g2_raw(
    "74ccc3ac9c383c60af083972b96d05c75f12c8907d128a17adafbab8c5a4acf7" +
    "01092ff4de89362670c21711b6dbe52dcd5f8e40c6654b3dece573c2ab3d29b2" +
    "44b0294aa04290e1524ff3e3da8cfd432bb64de3a8040b5b88d1b5fc86a4ebc1" +
    "8cfc48fb4ff37f1e27727464f3c34e2153861ad08e972d1625fc1a7bd18d5539",
  )
  let r_a = must_fn(
    "00005879dd1d51e175946f23b1b41e93ba31c584ae59a426ec1046a4d03b06c8",
  )
  let r_b = must_fn(
    "00018b98c44bef9f8537fb7d071b2c928b3bc65bd3d69e1eee213564905634fe",
  )
  (p_pub_e, de_a, de_b, r_a, r_b)
}

///|
test "GB/T 38635.3 Appendix A official test vector: exact byte-for-byte match" {
  let (p_pub_e, de_a, de_b, r_a, r_b) = official_fixture()
  let id_a = b"Alice"
  let id_b = b"Bob"
  // Sanity-check master public key P_pub-e = [ke]P1
  let ke = must_fn(
    "0002e65b0762d042f51f0d23542b13ed8cfa2e9a0e7206361e013a283905e31f",
  )
  assert_eq(@ec.G1Affine::generator().scalar_mul_fn(ke).to_affine(), p_pub_e)
  // Step A1-A3: User A generates R_A = [r_A]Q_B
  let r_a_point = match @keyex.generate_ephemeral(p_pub_e, id_b, r_a) {
    Ok(pt) => pt
    Err(e) => abort("generate_ephemeral(R_A) failed: \{e}")
  }
  let expected_ra = "7cba5b19069ee66aa79d490413d11846b9ba76dd22567f809cf23b6d964bb265" +
    "a9760c99cb6f706343fed05637085864958d6c90902aba7d405fbedf7b781599"
  assert_eq(@sm3.bytes_to_hex(r_a_point.to_bytes_raw()), expected_ra)
  // Step B1-B3: User B generates R_B = [r_B]Q_A
  let r_b_point = match @keyex.generate_ephemeral(p_pub_e, id_a, r_b) {
    Ok(pt) => pt
    Err(e) => abort("generate_ephemeral(R_B) failed: \{e}")
  }
  let expected_rb = "861e91485fb7623d2794f495031a35598b493bd45be37813abc710fcc1f34482" +
    "32d906a469ebc1216a802a7052d5617cd430fb56fba729d41d9bd668e9eb9600"
  assert_eq(@sm3.bytes_to_hex(r_b_point.to_bytes_raw()), expected_rb)
  // Step B5-B8: Responder B derives SK_B (16B), S_B (0x82), and S_2 (0x83)
  let res_b = match
    @keyex.responder_exchange(
      p_pub_e, id_a, id_b, de_b, r_b, r_a_point, r_b_point, 16,
    ) {
    Ok(res) => res
    Err(e) => abort("responder_exchange failed: \{e}")
  }
  let expected_sk = "c5c13a8f59a97cdeae64f16a2272a9e7"
  let expected_sb = "3bb4bcee8139c960b4d6566db1e0d5f0b2767680e5e1bf934103e6c66e40ffee"
  let expected_sa = "195d1b7256ba7e0e67c71202a25f8c94ff8241702c2f55d613ae1c6b98215172"
  assert_eq(@sm3.bytes_to_hex(res_b.sk), expected_sk)
  assert_eq(@sm3.bytes_to_hex(res_b.s_b), expected_sb)
  assert_eq(@sm3.bytes_to_hex(res_b.s_2), expected_sa)
  // Step A5-A8: Initiator A verifies S_B and derives SK_A, S_1, S_A
  let res_a = match
    @keyex.initiator_exchange(
      p_pub_e,
      id_a,
      id_b,
      de_a,
      r_a,
      r_a_point,
      r_b_point,
      16,
      peer_s_b=res_b.s_b,
    ) {
    Ok(res) => res
    Err(e) => abort("initiator_exchange failed: \{e}")
  }
  assert_eq(@sm3.bytes_to_hex(res_a.sk), expected_sk)
  assert_eq(@sm3.bytes_to_hex(res_a.s_1), expected_sb)
  assert_eq(@sm3.bytes_to_hex(res_a.s_a), expected_sa)
  assert_eq(res_a.sk, res_b.sk)
  assert_eq(res_a.s_1, res_b.s_b)
  assert_eq(res_a.s_a, res_b.s_2)
  // Initiator exchange without optional peer_s_b produces identical outputs
  let res_a_no_confirm = match
    @keyex.initiator_exchange(
      p_pub_e, id_a, id_b, de_a, r_a, r_a_point, r_b_point, 16,
    ) {
    Ok(res) => res
    Err(e) => abort("initiator_exchange (no peer_s_b) failed: \{e}")
  }
  assert_eq(res_a_no_confirm, res_a)
  // Step B9: Responder B verifies S_A against S_2
  assert_true(@keyex.verify_responder_confirmation(res_b.s_2, res_a.s_a))
}

///|
test "Arbitrary key lengths (16B, 32B, 64B) and full mutual-confirmation handshake" {
  let (p_pub_e, de_a, de_b, _, _) = official_fixture()
  let id_a = b"Alice"
  let id_b = b"Bob"
  // Use fresh non-fixture ephemeral scalars for an independent handshake
  let r_a = must_fn(
    "11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff",
  )
  let r_b = must_fn(
    "0f1e2d3c4b5a69788796a5b4c3d2e1f00123456789abcdef0123456789abcdef",
  )
  let ra_pt = match @keyex.generate_ephemeral(p_pub_e, id_b, r_a) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let rb_pt = match @keyex.generate_ephemeral(p_pub_e, id_a, r_b) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let lengths : Array[Int32] = [16, 32, 64]
  let keys : Array[Bytes] = []
  for i = 0; i < lengths.length(); i = i + 1 {
    let klen = lengths[i]
    let res_b = match
      @keyex.responder_exchange(
        p_pub_e, id_a, id_b, de_b, r_b, ra_pt, rb_pt, klen,
      ) {
      Ok(r) => r
      Err(e) => abort(e)
    }
    let res_a = match
      @keyex.initiator_exchange(
        p_pub_e,
        id_a,
        id_b,
        de_a,
        r_a,
        ra_pt,
        rb_pt,
        klen,
        peer_s_b=res_b.s_b,
      ) {
      Ok(r) => r
      Err(e) => abort(e)
    }
    assert_eq(res_b.sk.length(), klen)
    assert_eq(res_a.sk.length(), klen)
    assert_eq(res_a.sk, res_b.sk)
    assert_eq(res_a.s_1, res_b.s_b)
    assert_eq(res_a.s_a, res_b.s_2)
    assert_true(@keyex.verify_responder_confirmation(res_b.s_2, res_a.s_a))
    keys.push(res_a.sk)
  }
  // KDF prefix consistency: SK(16B) is prefix of SK(32B), which is prefix of SK(64B)
  assert_true(@sm3.ct_eq_bytes(keys[0], keys[1][0:16]))
  assert_true(@sm3.ct_eq_bytes(keys[1], keys[2][0:32]))
}

///|
test "Adversarial: reject infinity points, zero scalars, and non-positive klen" {
  let (p_pub_e, de_a, de_b, r_a, r_b) = official_fixture()
  let id_a = b"Alice"
  let id_b = b"Bob"
  let ra_pt = match @keyex.generate_ephemeral(p_pub_e, id_b, r_a) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let rb_pt = match @keyex.generate_ephemeral(p_pub_e, id_a, r_b) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let g1_inf = @ec.G1Affine::identity()
  let g2_inf = @ec.G2Affine::identity()
  let zero_fn = @field.Fn::zero()
  // generate_ephemeral rejections
  assert_true(@keyex.generate_ephemeral(g1_inf, id_b, r_a) is Err(_))
  assert_true(@keyex.generate_ephemeral(p_pub_e, id_b, zero_fn) is Err(_))
  // responder_exchange rejections: infinity R_A, infinity R_B, infinity P_pub-e, infinity de_B, zero r_B, klen <= 0
  assert_true(
    @keyex.responder_exchange(p_pub_e, id_a, id_b, de_b, r_b, g1_inf, rb_pt, 16)
    is Err(_),
  )
  assert_true(
    @keyex.responder_exchange(p_pub_e, id_a, id_b, de_b, r_b, ra_pt, g1_inf, 16)
    is Err(_),
  )
  assert_true(
    @keyex.responder_exchange(g1_inf, id_a, id_b, de_b, r_b, ra_pt, rb_pt, 16)
    is Err(_),
  )
  assert_true(
    @keyex.responder_exchange(
      p_pub_e, id_a, id_b, g2_inf, r_b, ra_pt, rb_pt, 16,
    )
    is Err(_),
  )
  assert_true(
    @keyex.responder_exchange(
      p_pub_e, id_a, id_b, de_b, zero_fn, ra_pt, rb_pt, 16,
    )
    is Err(_),
  )
  assert_true(
    @keyex.responder_exchange(p_pub_e, id_a, id_b, de_b, r_b, ra_pt, rb_pt, 0)
    is Err(_),
  )
  assert_true(
    @keyex.responder_exchange(p_pub_e, id_a, id_b, de_b, r_b, ra_pt, rb_pt, -16)
    is Err(_),
  )
  // initiator_exchange rejections: infinity R_A, infinity R_B, infinity P_pub-e, infinity de_A, zero r_A, klen <= 0
  assert_true(
    @keyex.initiator_exchange(p_pub_e, id_a, id_b, de_a, r_a, g1_inf, rb_pt, 16)
    is Err(_),
  )
  assert_true(
    @keyex.initiator_exchange(p_pub_e, id_a, id_b, de_a, r_a, ra_pt, g1_inf, 16)
    is Err(_),
  )
  assert_true(
    @keyex.initiator_exchange(g1_inf, id_a, id_b, de_a, r_a, ra_pt, rb_pt, 16)
    is Err(_),
  )
  assert_true(
    @keyex.initiator_exchange(
      p_pub_e, id_a, id_b, g2_inf, r_a, ra_pt, rb_pt, 16,
    )
    is Err(_),
  )
  assert_true(
    @keyex.initiator_exchange(
      p_pub_e, id_a, id_b, de_a, zero_fn, ra_pt, rb_pt, 16,
    )
    is Err(_),
  )
  assert_true(
    @keyex.initiator_exchange(p_pub_e, id_a, id_b, de_a, r_a, ra_pt, rb_pt, 0)
    is Err(_),
  )
  assert_true(
    @keyex.initiator_exchange(p_pub_e, id_a, id_b, de_a, r_a, ra_pt, rb_pt, -1)
    is Err(_),
  )
}

///|
test "Adversarial: tampered S_B, tampered S_A, and swapped ID_A/ID_B fail confirmation" {
  let (p_pub_e, de_a, de_b, r_a, r_b) = official_fixture()
  let id_a = b"Alice"
  let id_b = b"Bob"
  let ra_pt = match @keyex.generate_ephemeral(p_pub_e, id_b, r_a) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let rb_pt = match @keyex.generate_ephemeral(p_pub_e, id_a, r_b) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let res_b = match
    @keyex.responder_exchange(p_pub_e, id_a, id_b, de_b, r_b, ra_pt, rb_pt, 16) {
    Ok(r) => r
    Err(e) => abort(e)
  }
  // 1. Tampered S_B (1-bit flip) causes initiator_exchange to fail immediately
  let bad_sb = flip_byte(res_b.s_b, 0)
  assert_eq(
    @keyex.initiator_exchange(
      p_pub_e,
      id_a,
      id_b,
      de_a,
      r_a,
      ra_pt,
      rb_pt,
      16,
      peer_s_b=bad_sb,
    ),
    Err("key confirmation S_B mismatch"),
  )
  // Truncated S_B also fails immediately
  assert_eq(
    @keyex.initiator_exchange(
      p_pub_e,
      id_a,
      id_b,
      de_a,
      r_a,
      ra_pt,
      rb_pt,
      16,
      peer_s_b=res_b.s_b[0:31],
    ),
    Err("key confirmation S_B mismatch"),
  )
  // 2. Tampered S_A causes responder confirmation verification to return false
  let res_a = match
    @keyex.initiator_exchange(
      p_pub_e,
      id_a,
      id_b,
      de_a,
      r_a,
      ra_pt,
      rb_pt,
      16,
      peer_s_b=res_b.s_b,
    ) {
    Ok(r) => r
    Err(e) => abort(e)
  }
  let bad_sa = flip_byte(res_a.s_a, 31)
  assert_true(!@keyex.verify_responder_confirmation(res_b.s_2, bad_sa))
  assert_true(!@keyex.verify_responder_confirmation(res_b.s_2, res_a.s_a[0:31]))
  assert_true(!@keyex.verify_responder_confirmation(b"", b""))
  // 3. Swapped ID_A / ID_B breaks S_B confirmation, SK agreement, and S_A confirmation
  assert_eq(
    @keyex.initiator_exchange(
      p_pub_e,
      id_b,
      id_a,
      de_a,
      r_a,
      ra_pt,
      rb_pt,
      16,
      peer_s_b=res_b.s_b,
    ),
    Err("key confirmation S_B mismatch"),
  )
  let res_a_swapped = match
    @keyex.initiator_exchange(p_pub_e, id_b, id_a, de_a, r_a, ra_pt, rb_pt, 16) {
    Ok(r) => r
    Err(e) => abort(e)
  }
  assert_true(res_a_swapped.sk != res_b.sk)
  assert_true(res_a_swapped.s_1 != res_b.s_b)
  assert_true(
    !@keyex.verify_responder_confirmation(res_b.s_2, res_a_swapped.s_a),
  )
}

///|
test "Adversarial: MAX_KDF_LEN bound enforcement and constant-time result equality" {
  let (p_pub_e, de_a, de_b, r_a, r_b) = official_fixture()
  let id_a = b"Alice"
  let id_b = b"Bob"
  let ra_pt = match @keyex.generate_ephemeral(p_pub_e, id_b, r_a) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let rb_pt = match @keyex.generate_ephemeral(p_pub_e, id_a, r_b) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  assert_eq(@keyex.MAX_KDF_LEN, 16_777_216)
  let over_klen = @keyex.MAX_KDF_LEN + 1
  assert_true(
    @keyex.responder_exchange(
      p_pub_e, id_a, id_b, de_b, r_b, ra_pt, rb_pt, over_klen,
    )
    is Err(_),
  )
  assert_true(
    @keyex.initiator_exchange(
      p_pub_e, id_a, id_b, de_a, r_a, ra_pt, rb_pt, over_klen,
    )
    is Err(_),
  )

  // Constant-time ct_eq / Eq on ResponderResult and InitiatorResult
  let res_b1 = match
    @keyex.responder_exchange(p_pub_e, id_a, id_b, de_b, r_b, ra_pt, rb_pt, 16) {
    Ok(r) => r
    Err(e) => abort(e)
  }
  let res_b2 = match
    @keyex.responder_exchange(p_pub_e, id_a, id_b, de_b, r_b, ra_pt, rb_pt, 16) {
    Ok(r) => r
    Err(e) => abort(e)
  }
  let res_b_32 = match
    @keyex.responder_exchange(p_pub_e, id_a, id_b, de_b, r_b, ra_pt, rb_pt, 32) {
    Ok(r) => r
    Err(e) => abort(e)
  }
  assert_true(res_b1.ct_eq(res_b2))
  assert_eq(res_b1, res_b2)
  assert_true(!res_b1.ct_eq(res_b_32))
  assert_true(res_b1 != res_b_32)

  let res_a1 = match
    @keyex.initiator_exchange(p_pub_e, id_a, id_b, de_a, r_a, ra_pt, rb_pt, 16) {
    Ok(r) => r
    Err(e) => abort(e)
  }
  let res_a2 = match
    @keyex.initiator_exchange(
      p_pub_e,
      id_a,
      id_b,
      de_a,
      r_a,
      ra_pt,
      rb_pt,
      16,
      peer_s_b=res_b1.s_b,
    ) {
    Ok(r) => r
    Err(e) => abort(e)
  }
  let res_a_32 = match
    @keyex.initiator_exchange(p_pub_e, id_a, id_b, de_a, r_a, ra_pt, rb_pt, 32) {
    Ok(r) => r
    Err(e) => abort(e)
  }
  assert_true(res_a1.ct_eq(res_a2))
  assert_eq(res_a1, res_a2)
  assert_true(!res_a1.ct_eq(res_a_32))
  assert_true(res_a1 != res_a_32)
}
