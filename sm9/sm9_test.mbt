///|
fn must_hex(hex : String) -> Bytes {
  match @sm9.hex_to_bytes(hex) {
    Some(b) => b
    None => abort("invalid hex literal in test")
  }
}

///|
fn must_fn(hex : String) -> @field.Fn {
  match @field.Fn::from_be_bytes_nonzero(must_hex(hex)) {
    Some(v) => v
    None => abort("invalid non-zero Fn literal in test")
  }
}

///|
fn must_fp(hex : String) -> @field.Fp {
  match @field.Fp::from_be_bytes_strict(must_hex(hex)) {
    Some(v) => v
    None => abort("invalid Fp literal in test")
  }
}

///|
fn flip_bit(data : BytesView, byte_idx : Int32, mask : Byte) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == byte_idx {
      (data[i].to_int() ^ mask.to_int()).to_byte()
    } else {
      data[i]
    }
  })
}

///|
fn derive_nonzero_scalar(label : BytesView) -> @field.Fn {
  let h = @sm9.sm3_hash(label)
  let v = @field.Fn::from_be_bytes_mod(h)
  if v.is_zero() {
    @field.Fn::one()
  } else {
    v
  }
}

///|
test "End-to-end GB/T 38635.2 Appendix A: KGC + Digital Signature via facade" {
  let id_a = b"Alice"
  let msg = b"Chinese IBS standard"
  let ks_hex = "000130e78459d78545cb54c587e02cf480ce0b66340f319f348a1d5b1f2dc5f4"
  let r_hex = "00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe"
  // 1. KGC master key pair
  let master = match @sm9.sign_master_from_bytes(must_hex(ks_hex)) {
    Some(k) => k
    None => abort("failed to load official ks")
  }
  let p_pub_s = master.public_key()
  assert_eq(
    @sm9.bytes_to_hex(p_pub_s.to_bytes_raw()),
    "9f64080b3084f733e48aff4b41b565011ce0711c5e392cfb0ab1b6791b94c408" +
    "29dba116152d1f786ce843ed24a3b573414d2177386a92dd8f14d65696ea5e32" +
    "69850938abea0112b57329f447e3a0cbad3e2fdb1a77f335e89e1408d0ef1c25" +
    "41e00a53dda532da1a7ce027b7a46f741006e85f5cdff0730e75c05fb4e3216d",
  )
  // 2. Extract Alice's signing private key ds_A
  let ds_a = match @sm9.extract_sign_key(master, id_a) {
    Ok(k) => k
    Err(e) => abort(e)
  }
  assert_eq(
    @sm9.bytes_to_hex(ds_a.to_bytes_raw()),
    "a5702f05cf1315305e2d6eb64b0deb923db1a0bcf0caff90523ac8754aa69820" +
    "78559a844411f9825c109f5ee3f52d720dd01785392a727bb1556952b2b013d3",
  )
  // 3. Verify g = e(P_pub-s, P1) matches Appendix A byte-for-byte
  let g = @sm9.pair(p_pub_s.to_g2(), @ec.G1Affine::generator())
  assert_eq(
    @sm9.bytes_to_hex(g.to_bytes()),
    "4e378fb5561cd0668f906b731ac58fee25738edf09cadc7a29c0abc0177aea6d" +
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
    "aab9f06a4eeba4323a7833db202e4e35639d93fa3305af73f0f071d7d284fcfb",
  )
  // 4. Sign with official nonce r and check exact (h, S)
  let r = must_fn(r_hex)
  let sig = match @sm9.sign_with_r(p_pub_s, ds_a, msg, r) {
    Ok(s) => s
    Err(e) => abort(e)
  }
  assert_eq(
    @sm9.bytes_to_hex(sig.h().to_be_bytes()),
    "823c4b21e4bd2dfe1ed92c606653e996668563152fc33f55d7bfbb9bd9705adb",
  )
  assert_eq(
    @sm9.bytes_to_hex(sig.s().to_bytes_raw()),
    "73bf96923ce58b6ad0e13e9643a406d8eb98417c50ef1b29cef9adb48b6d598c" +
    "856712f1c2e0968ab7769f42a99586aed139d5b8b3e15891827cc2aced9baa05",
  )
  assert_true(@sm9.verify(p_pub_s, id_a, msg, sig))
  // Serialization round-trips (96B raw and 97B uncompressed)
  assert_eq(
    @sign.Signature::from_bytes_raw_strict(sig.to_bytes_raw()),
    Some(sig),
  )
  assert_eq(
    @sign.Signature::from_bytes_uncompressed_strict(sig.to_bytes_uncompressed()),
    Some(sig),
  )
  // 5. Deterministic facade signing + verification
  let det_sig1 = match @sm9.sign(p_pub_s, ds_a, msg) {
    Ok(s) => s
    Err(e) => abort(e)
  }
  let det_sig2 = match @sm9.sign(p_pub_s, ds_a, msg) {
    Ok(s) => s
    Err(e) => abort(e)
  }
  let det_sig_ent = match
    @sm9.sign(p_pub_s, ds_a, msg, entropy=b"extra-entropy-01") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  assert_eq(det_sig1, det_sig2)
  assert_true(det_sig1 != det_sig_ent)
  assert_true(@sm9.verify(p_pub_s, id_a, msg, det_sig1))
  assert_true(@sm9.verify(p_pub_s, id_a, msg, det_sig_ent))
}

///|
test "End-to-end GB/T 38635.3 Appendix A: KGC + Key Exchange via facade" {
  let id_a = b"Alice"
  let id_b = b"Bob"
  let ke_hex = "0002e65b0762d042f51f0d23542b13ed8cfa2e9a0e7206361e013a283905e31f"
  let ra_hex = "00005879dd1d51e175946f23b1b41e93ba31c584ae59a426ec1046a4d03b06c8"
  let rb_hex = "00018b98c44bef9f8537fb7d071b2c928b3bc65bd3d69e1eee213564905634fe"
  let master = match @sm9.enc_master_from_bytes(must_hex(ke_hex)) {
    Some(k) => k
    None => abort("failed to load Part 3 ke")
  }
  let p_pub_e = master.public_key()
  assert_eq(
    @sm9.bytes_to_hex(p_pub_e.to_bytes_raw()),
    "9174542668e8f14ab273c0945c3690c66e5dd09678b86f734c4350567ed06283" +
    "54e598c6bf749a3dacc9fffedd9db6866c50457cfc7aa2a4ad65c3168ff74210",
  )
  let de_a = match @sm9.extract_keyex_key(master, id_a) {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let de_b = match @sm9.extract_keyex_key(master, id_b) {
    Ok(k) => k
    Err(e) => abort(e)
  }
  assert_eq(
    @sm9.bytes_to_hex(de_a.to_bytes_raw()),
    "0fe8eab395199b56bf1d75bd2cd610b6424f08d1092922c5882b52dcd6ca832a" +
    "7da57bc50241f9e5bfddc075dd9d32c7777100d736916cfc165d8d36e0634cd7" +
    "83a457daf52cad464c903b26062caf937bb40e37daded9eda401050e49c8ad0c" +
    "6970876b9aad1b7a50bb4863a11e574af1fe3c5975161d73de4c3af621fb1efb",
  )
  assert_eq(
    @sm9.bytes_to_hex(de_b.to_bytes_raw()),
    "74ccc3ac9c383c60af083972b96d05c75f12c8907d128a17adafbab8c5a4acf7" +
    "01092ff4de89362670c21711b6dbe52dcd5f8e40c6654b3dece573c2ab3d29b2" +
    "44b0294aa04290e1524ff3e3da8cfd432bb64de3a8040b5b88d1b5fc86a4ebc1" +
    "8cfc48fb4ff37f1e27727464f3c34e2153861ad08e972d1625fc1a7bd18d5539",
  )
  let r_a = must_fn(ra_hex)
  let r_b = must_fn(rb_hex)
  let ra_pt = match @sm9.keyex_ephemeral(p_pub_e, id_b, r_a) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let rb_pt = match @sm9.keyex_ephemeral(p_pub_e, id_a, r_b) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  assert_eq(
    @sm9.bytes_to_hex(ra_pt.to_bytes_raw()),
    "7cba5b19069ee66aa79d490413d11846b9ba76dd22567f809cf23b6d964bb265" +
    "a9760c99cb6f706343fed05637085864958d6c90902aba7d405fbedf7b781599",
  )
  assert_eq(
    @sm9.bytes_to_hex(rb_pt.to_bytes_raw()),
    "861e91485fb7623d2794f495031a35598b493bd45be37813abc710fcc1f34482" +
    "32d906a469ebc1216a802a7052d5617cd430fb56fba729d41d9bd668e9eb9600",
  )
  let resp = match
    @sm9.keyex_responder(p_pub_e, id_a, id_b, de_b, r_b, ra_pt, rb_pt, 16) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  let init = match
    @sm9.keyex_initiator(
      p_pub_e,
      id_a,
      id_b,
      de_a,
      r_a,
      ra_pt,
      rb_pt,
      16,
      peer_s_b=resp.s_b,
    ) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(@sm9.bytes_to_hex(resp.sk), "c5c13a8f59a97cdeae64f16a2272a9e7")
  assert_eq(resp.sk, init.sk)
  assert_eq(
    @sm9.bytes_to_hex(resp.s_b),
    "3bb4bcee8139c960b4d6566db1e0d5f0b2767680e5e1bf934103e6c66e40ffee",
  )
  assert_eq(resp.s_b, init.s_1)
  assert_eq(
    @sm9.bytes_to_hex(init.s_a),
    "195d1b7256ba7e0e67c71202a25f8c94ff8241702c2f55d613ae1c6b98215172",
  )
  assert_eq(resp.s_2, init.s_a)
  assert_true(@sm9.keyex_verify_confirmation(resp.s_2, init.s_a))
}

///|
test "End-to-end GB/T 38635.4 Appendix A.1/A.2/A.3: KGC + KEM + KdfXor + Sm4EcbPkcs7 via facade" {
  let id_b = b"Bob"
  let msg = b"Chinese IBE standard"
  let ke_hex = "0001edee3778f441f8dea3d9fa0acc4e07ee36c93f9a08618af4ad85cede1c22"
  let master = match @sm9.enc_master_from_bytes(must_hex(ke_hex)) {
    Some(k) => k
    None => abort("failed to load Part 4 ke")
  }
  let p_pub_e = master.public_key()
  assert_eq(
    @sm9.bytes_to_hex(p_pub_e.to_bytes_raw()),
    "787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff" +
    "769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1",
  )
  let de_b = match @sm9.extract_enc_key(master, id_b) {
    Ok(k) => k
    Err(e) => abort(e)
  }
  assert_eq(
    @sm9.bytes_to_hex(de_b.to_bytes_raw()),
    "94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683" +
    "115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b158" +
    "7aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f" +
    "27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1",
  )
  // Verify g = e(P2, P_pub-e)
  let g = @sm9.pair(@ec.G2Affine::generator(), p_pub_e.to_g1())
  assert_eq(
    @sm9.bytes_to_hex(g.to_bytes()),
    "9746fc5b231cedf36f835c47893d63c6ff652bcb92375ce3c2ab256d1fd56413" +
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
    "9ce7bc68062182cf5d9f4a98c5a4ed1f3b4ce4ea817d19ed7ef2ce98e6f5864d",
  )
  // Appendix A.1: KEM
  let r_a1 = must_fn(
    "000074015f8489c01ef4270456f9e6475bfb602bde7f33fd482ab4e3684a6722",
  )
  let kem_out = match @sm9.kem_encapsulate_with_r(p_pub_e, id_b, 32, r_a1) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(
    @sm9.bytes_to_hex(kem_out.c1_bytes_raw()),
    "1edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f" +
    "1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c",
  )
  assert_eq(
    @sm9.bytes_to_hex(kem_out.key()),
    "4ff5cf86d2ad40c8f4bac98d76abdbde0c0e2f0a829d3f911ef5b2bce0695480",
  )
  let kem_decap = match @sm9.kem_decapsulate(id_b, de_b, kem_out.c1(), 32) {
    Ok(k) => k
    Err(e) => abort(e)
  }
  assert_eq(kem_decap, kem_out.key())
  // Deterministic KEM round-trip (requires >= 32 bytes CSPRNG entropy)
  let kem_entropy = @sm9.sm3_hash(b"kem-seed-42")
  assert_eq(@sm9.MIN_ENTROPY_LEN, 32)
  assert_eq(kem_entropy.length(), 32)
  let det_kem = match @sm9.kem_encapsulate(p_pub_e, id_b, 48, kem_entropy) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_eq(
    @sm9.kem_decapsulate(id_b, de_b, det_kem.c1(), 48),
    Ok(det_kem.key()),
  )
  // Adversarial: empty and short (< 32B) entropy must be rejected by kem_encapsulate
  assert_true(@sm9.kem_encapsulate(p_pub_e, id_b, 32, b"") is Err(_))
  assert_true(
    @sm9.kem_encapsulate(p_pub_e, id_b, 32, Bytes::make(16, b'\x42')) is Err(_),
  )
  assert_true(
    @sm9.kem_encapsulate(p_pub_e, id_b, 32, Bytes::make(31, b'\x42')) is Err(_),
  )
  // Appendix A.2: KDF-XOR Encryption
  let r_a2 = must_fn(
    "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )
  let ct_xor = match
    @sm9.encrypt_with_r(p_pub_e, id_b, msg, r_a2, mode=@enc.EncMode::KdfXor) {
    Ok(c) => c
    Err(e) => abort(e)
  }
  assert_eq(ct_xor.length(), 116)
  assert_eq(
    @sm9.bytes_to_hex(ct_xor),
    "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff" +
    "42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0" +
    "ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f367" +
    "1b5f5b0e951489682f3e64e1378cdd5da9513b1c",
  )
  assert_eq(
    @sm9.decrypt(id_b, de_b, ct_xor, mode=@enc.EncMode::KdfXor),
    Ok(msg),
  )
  // Appendix A.3: SM4-ECB-PKCS#7 Encryption
  let ct_sm4 = match
    @sm9.encrypt_with_r(
      p_pub_e,
      id_b,
      msg,
      r_a2,
      mode=@enc.EncMode::Sm4EcbPkcs7,
    ) {
    Ok(c) => c
    Err(e) => abort(e)
  }
  assert_eq(ct_sm4.length(), 128)
  assert_eq(
    @sm9.bytes_to_hex(ct_sm4),
    "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff" +
    "42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0" +
    "fd3c98dd92c44c68332675a370cceede31e0c5cd209c257601149d12b394a2be" +
    "e05b6fac6f11b965268c994f00dba7a8bb00fd60583546cbdf4649250863f10a",
  )
  assert_eq(
    @sm9.decrypt(id_b, de_b, ct_sm4, mode=@enc.EncMode::Sm4EcbPkcs7),
    Ok(msg),
  )
  // Deterministic encryption round-trips across edge plaintext sizes (0B, 15B, 16B, 17B)
  let samples : FixedArray[Bytes] = [
    b"", b"123456789012345", b"0123456789abcdef", b"0123456789abcdef!",
  ]
  for i = 0; i < samples.length(); i = i + 1 {
    let pt = samples[i]
    let xor_ent = Bytes::makei(32, fn(j) { ((i * 37 + j + 1) & 0xff).to_byte() })
    let sm4_ent = Bytes::makei(32, fn(j) {
      ((i * 53 + j + 0x80) & 0xff).to_byte()
    })
    let c_xor = match
      @sm9.encrypt(p_pub_e, id_b, pt, xor_ent, mode=@enc.EncMode::KdfXor) {
      Ok(c) => c
      Err(e) => abort(e)
    }
    assert_eq(
      @sm9.decrypt(id_b, de_b, c_xor, mode=@enc.EncMode::KdfXor),
      Ok(pt),
    )
    let c_sm4 = match
      @sm9.encrypt(p_pub_e, id_b, pt, sm4_ent, mode=@enc.EncMode::Sm4EcbPkcs7) {
      Ok(c) => c
      Err(e) => abort(e)
    }
    assert_eq(
      @sm9.decrypt(id_b, de_b, c_sm4, mode=@enc.EncMode::Sm4EcbPkcs7),
      Ok(pt),
    )
  }
  // Adversarial: empty and short (< 32B) entropy must be rejected by encrypt in both modes
  let short16 = Bytes::make(16, b'\x5a')
  let short31 = Bytes::make(31, b'\x5a')
  assert_true(
    @sm9.encrypt(p_pub_e, id_b, msg, b"", mode=@enc.EncMode::KdfXor) is Err(_),
  )
  assert_true(
    @sm9.encrypt(p_pub_e, id_b, msg, short16, mode=@enc.EncMode::KdfXor)
    is Err(_),
  )
  assert_true(
    @sm9.encrypt(p_pub_e, id_b, msg, short31, mode=@enc.EncMode::KdfXor)
    is Err(_),
  )
  assert_true(
    @sm9.encrypt(p_pub_e, id_b, msg, b"", mode=@enc.EncMode::Sm4EcbPkcs7)
    is Err(_),
  )
  assert_true(
    @sm9.encrypt(p_pub_e, id_b, msg, short16, mode=@enc.EncMode::Sm4EcbPkcs7)
    is Err(_),
  )
  assert_true(
    @sm9.encrypt(p_pub_e, id_b, msg, short31, mode=@enc.EncMode::Sm4EcbPkcs7)
    is Err(_),
  )
}

///|
test "Bilinearity, additivity, non-degeneracy, inversion, prime order, and KGC pairing invariants" {
  let p1 = @ec.G1Affine::generator()
  let p2 = @ec.G2Affine::generator()
  let e_base = @sm9.pair(p2, p1)
  // Non-degeneracy and exact official base pairing e(P2, P1)
  assert_true(!e_base.is_zero())
  assert_true(!e_base.is_one())
  assert_eq(
    @sm9.bytes_to_hex(e_base.to_bytes()),
    "256943fbdb2bf87ab91ae7fbeaff14e146cf7e2279b9d155d13461e09b22f523" +
    "0167b0280051495c6af1ec23ba2cd2ff1cdcdeca461a5ab0b5449e9091308310" +
    "5e7addaddf7fbfe16291b4e89af50b8217ddc47ba3cba833c6e77c3fb027685e" +
    "79d0c8337072c93fef482bb055f44d6247ccac8e8e12525854b3566236337ebe" +
    "082cde173022da8cd09b28a2d80a8cee53894436a52007f978dc37f36116d39b" +
    "3fa7ed741eaed99a58f53e3df82df7ccd3407bcc7b1d44a9441920ced5fb824f" +
    "7fc6eb2aa771d99c9234fddd31752edfd60723e05a4ebfdeb5c33fbd47e0cf06" +
    "6fa6b6fa6dd6b6d3b19a959a110e748154eef796dc0fc2dd766ea414de786968" +
    "8ffe1c0e9de45fd0fed790ac26be91f6b3f0a49c084fe29a3fb6ed288ad7994d" +
    "1664a1366beb3196f0443e15f5f9042a947354a5678430d45ba031cff06db927" +
    "7f7c6d52b475e6aaa827fdc5b4175ac6929320f782d998f86b6b57cda42a0426" +
    "36a699de7c136f78eee2dbac4ca9727bff0cee02ee920f5822e65ea170aa9669",
  )
  // Inversion: e(-P2, P1) == e(P2, -P1) == e(P2, P1).conjugate() and e(-P2, -P1) == e(P2, P1)
  let e_conj = e_base.conjugate()
  assert_eq(@sm9.pair(p2.neg(), p1), e_conj)
  assert_eq(@sm9.pair(p2, p1.neg()), e_conj)
  assert_eq(@sm9.pair(p2.neg(), p1.neg()), e_base)
  assert_eq(e_base.mul(e_conj), @field.Fp12::one())
  // Prime order N in GT: e(P2, P1)^N == 1
  assert_eq(e_base.cyclotomic_pow_u256(@field.order_n), @field.Fp12::one())
  // Multi-triple deterministic SM3-derived scalar bilinearity & additivity property tests
  let seeds : FixedArray[(Bytes, Bytes, Bytes)] = [
    (b"prop-a-0", b"prop-b-0", b"prop-c-0"),
    (b"prop-a-1", b"prop-b-1", b"prop-c-1"),
    (b"prop-a-2", b"prop-b-2", b"prop-c-2"),
  ]
  for i = 0; i < seeds.length(); i = i + 1 {
    let (sa, sb, sc) = seeds[i]
    let a = derive_nonzero_scalar(sa)
    let b = derive_nonzero_scalar(sb)
    let c = derive_nonzero_scalar(sc)
    let ab = a.mul(b)
    let pa = p1.scalar_mul_fn(a).to_affine()
    let pb = p1.scalar_mul_fn(b).to_affine()
    let pc = p1.scalar_mul_fn(c).to_affine()
    let pab = p1.scalar_mul_fn(ab).to_affine()
    let qa = p2.scalar_mul_fn(a).to_affine()
    let qb = p2.scalar_mul_fn(b).to_affine()
    let qc = p2.scalar_mul_fn(c).to_affine()
    let qab = p2.scalar_mul_fn(ab).to_affine()
    // e([a]P2, [b]P1) == e(P2, P1)^(a*b) == e([b]P2, [a]P1) == e([a*b]P2, P1) == e(P2, [a*b]P1)
    let lhs = @sm9.pair(qa, pb)
    let expected = e_base.cyclotomic_pow_u256(ab.to_u256())
    assert_eq(lhs, expected)
    assert_eq(@sm9.pair(qb, pa), expected)
    assert_eq(@sm9.pair(qab, p1), expected)
    assert_eq(@sm9.pair(p2, pab), expected)
    // G1 additivity: e(Q, P_a + P_b) == e(Q, P_a) * e(Q, P_b)
    let pa_plus_pb = pa.to_jac().add_mixed(pb).to_affine()
    assert_eq(
      @sm9.pair(qc, pa_plus_pb),
      @sm9.pair(qc, pa).mul(@sm9.pair(qc, pb)),
    )
    // G2 additivity: e(Q_a + Q_b, P) == e(Q_a, P) * e(Q_b, P)
    let qa_plus_qb = qa.to_jac().add_mixed(qb).to_affine()
    assert_eq(
      @sm9.pair(qa_plus_qb, pc),
      @sm9.pair(qa, pc).mul(@sm9.pair(qb, pc)),
    )
    // Multi-pairing product consistency
    assert_eq(@sm9.pair_product(qa, pb, qc, pa), lhs.mul(@sm9.pair(qc, pa)))
  }
  // KGC pairing invariants via seed-derived master keys
  let sign_master = @sm9.sign_master_from_seed(b"kgc-invariant-sign-seed")
  let p_pub_s = sign_master.public_key()
  let ds_alice = match @sm9.extract_sign_key(sign_master, b"alice@sm9") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let p_alice = @kgc.derive_sign_user_public_point(p_pub_s, b"alice@sm9")
  assert_eq(
    @sm9.pair(p_alice, ds_alice.to_g1()),
    @sm9.pair(p_pub_s.to_g2(), p1),
  )
  let enc_master = @sm9.enc_master_from_seed(b"kgc-invariant-enc-seed")
  let p_pub_e = enc_master.public_key()
  let de_keyex = match @sm9.extract_keyex_key(enc_master, b"bob@sm9") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let q_keyex = @kgc.derive_enc_user_public_point(
    p_pub_e,
    b"bob@sm9",
    @sm9.HID_KEYEX,
  )
  assert_eq(
    @sm9.pair(de_keyex.to_g2(), q_keyex),
    @sm9.pair(p2, p_pub_e.to_g1()),
  )
  let de_enc = match @sm9.extract_enc_key(enc_master, b"bob@sm9") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let q_enc = @kgc.derive_enc_user_public_point(
    p_pub_e,
    b"bob@sm9",
    @sm9.HID_ENC,
  )
  assert_eq(@sm9.pair(de_enc.to_g2(), q_enc), @sm9.pair(p2, p_pub_e.to_g1()))
}

///|
test "Adversarial malformed curve points: off-curve, >=p, infinity, bad prefix, wrong twist, and G2 cofactor" {
  let p1 = @ec.G1Affine::generator()
  let p2 = @ec.G2Affine::generator()
  let p_bytes = @field.modulus_p.to_be_bytes()
  // 1. Off-curve G1 point (x_P1, y_P1 + 1)
  let bad_g1_y = p1.y().add(@field.Fp::one())
  let off_g1_raw = Bytes::makei(64, fn(i) {
    if i < 32 {
      p1.x().to_be_bytes()[i]
    } else {
      bad_g1_y.to_be_bytes()[i - 32]
    }
  })
  assert_true(@ec.G1Affine::from_bytes_raw_strict(off_g1_raw) is None)
  assert_true(
    @kgc.EncMasterPublicKey::from_bytes_raw_strict(off_g1_raw) is None,
  )
  assert_true(
    @kgc.SignUserPrivateKey::from_bytes_raw_strict(off_g1_raw) is None,
  )
  // 2. Out-of-range (>= p) coordinates for G1 and G2
  let ge_p_g1 = Bytes::makei(64, fn(i) {
    if i < 32 {
      p_bytes[i]
    } else {
      p1.y().to_be_bytes()[i - 32]
    }
  })
  assert_true(@ec.G1Affine::from_bytes_raw_strict(ge_p_g1) is None)
  assert_true(@kgc.EncMasterPublicKey::from_bytes_raw_strict(ge_p_g1) is None)
  let p2_raw = p2.to_bytes_raw()
  let ge_p_g2 = Bytes::makei(128, fn(i) {
    if i < 32 {
      p_bytes[i]
    } else {
      p2_raw[i]
    }
  })
  assert_true(@ec.G2Affine::from_bytes_raw_strict(ge_p_g2) is None)
  assert_true(@kgc.SignMasterPublicKey::from_bytes_raw_strict(ge_p_g2) is None)
  assert_true(@kgc.EncUserPrivateKey::from_bytes_raw_strict(ge_p_g2) is None)
  // 3. All-zero infinity encodings rejected everywhere
  let zero64 = Bytes::make(64, b'\x00')
  let zero65 = Bytes::makei(65, fn(i) { if i == 0 { b'\x04' } else { b'\x00' } })
  let zero128 = Bytes::make(128, b'\x00')
  let zero129 = Bytes::makei(129, fn(i) {
    if i == 0 {
      b'\x04'
    } else {
      b'\x00'
    }
  })
  assert_true(@ec.G1Affine::from_bytes_raw_strict(zero64) is None)
  assert_true(@ec.G1Affine::from_bytes_uncompressed_strict(zero65) is None)
  assert_true(@kgc.EncMasterPublicKey::from_bytes_raw_strict(zero64) is None)
  assert_true(@kgc.SignUserPrivateKey::from_bytes_raw_strict(zero64) is None)
  assert_true(@ec.G2Affine::from_bytes_raw_strict(zero128) is None)
  assert_true(@ec.G2Affine::from_bytes_uncompressed_strict(zero129) is None)
  assert_true(@kgc.SignMasterPublicKey::from_bytes_raw_strict(zero128) is None)
  assert_true(@kgc.EncUserPrivateKey::from_bytes_raw_strict(zero128) is None)
  // 4. Wrong 0x04 prefix for uncompressed G1 and G2
  let p1_unc = p1.to_bytes_uncompressed()
  let bad_prefix_g1 = flip_bit(p1_unc, 0, b'\x01')
  assert_true(
    @kgc.EncMasterPublicKey::from_bytes_uncompressed_strict(bad_prefix_g1)
    is None,
  )
  assert_true(
    @kgc.SignUserPrivateKey::from_bytes_uncompressed_strict(bad_prefix_g1)
    is None,
  )
  let p2_unc = p2.to_bytes_uncompressed()
  let bad_prefix_g2 = flip_bit(p2_unc, 0, b'\x01')
  assert_true(
    @kgc.SignMasterPublicKey::from_bytes_uncompressed_strict(bad_prefix_g2)
    is None,
  )
  assert_true(
    @kgc.EncUserPrivateKey::from_bytes_uncompressed_strict(bad_prefix_g2)
    is None,
  )
  // 5. Wrong-twist G2 point on y^2 = x^3 + 5/u (must be rejected across all KGC/EC parsers)
  let wt_x = @field.Fp2::new(
    must_fp("0000000000000000000000000000000000000000000000000000000000000002"),
    must_fp("0000000000000000000000000000000000000000000000000000000000000001"),
  )
  let wt_y = @field.Fp2::new(
    must_fp("718da4efb433867d47e25eeb9706c91c429177370bc52c19e72086bc07d630be"),
    must_fp("64430ad9bb77e6a1e74108282f7a6631946a0764171c1e7e41cabcd2844c125f"),
  )
  let five_over_u = @field.Fp2::from_fp(@field.Fp::b_const()).mul(
    @field.Fp2::new(@field.Fp::zero(), @field.Fp::one()).inv(),
  )
  assert_eq(wt_y.sqr(), wt_x.sqr().mul(wt_x).add(five_over_u))
  let wt_raw = must_hex(
    "0000000000000000000000000000000000000000000000000000000000000001" +
    "0000000000000000000000000000000000000000000000000000000000000002" +
    "64430ad9bb77e6a1e74108282f7a6631946a0764171c1e7e41cabcd2844c125f" +
    "718da4efb433867d47e25eeb9706c91c429177370bc52c19e72086bc07d630be",
  )
  assert_true(@ec.G2Affine::from_coords_checked(wt_x, wt_y) is None)
  assert_true(@kgc.SignMasterPublicKey::from_bytes_raw_strict(wt_raw) is None)
  assert_true(@kgc.EncUserPrivateKey::from_bytes_raw_strict(wt_raw) is None)
  // 6. Cofactor G2 point: satisfies y^2 = x^3 + 5u on E'(Fp2), NOT in prime-order G2 subgroup!
  let cf_x = @field.Fp2::new(
    must_fp("0000000000000000000000000000000000000000000000000000000000000001"),
    must_fp("0000000000000000000000000000000000000000000000000000000000000001"),
  )
  let cf_y = @field.Fp2::new(
    must_fp("9782d17c0113ff75963b71b2afb4eb089a6c6ac94e599b48be78baaf3a5d5f96"),
    must_fp("9324098b67dd1ccfb2bc8054215aaf13516d207bd61c4b8b3876c76edf7aa9ec"),
  )
  assert_eq(cf_y.sqr(), cf_x.sqr().mul(cf_x).add(@field.Fp2::b_twist()))
  let cf_raw = must_hex(
    "0000000000000000000000000000000000000000000000000000000000000001" +
    "0000000000000000000000000000000000000000000000000000000000000001" +
    "9324098b67dd1ccfb2bc8054215aaf13516d207bd61c4b8b3876c76edf7aa9ec" +
    "9782d17c0113ff75963b71b2afb4eb089a6c6ac94e599b48be78baaf3a5d5f96",
  )
  let cf_unc = Bytes::makei(129, fn(i) {
    if i == 0 {
      b'\x04'
    } else {
      cf_raw[i - 1]
    }
  })
  assert_true(@ec.G2Affine::from_coords_checked(cf_x, cf_y) is None)
  assert_true(@ec.G2Affine::from_bytes_raw_strict(cf_raw) is None)
  assert_true(@ec.G2Affine::from_bytes_uncompressed_strict(cf_unc) is None)
  assert_true(@kgc.SignMasterPublicKey::from_bytes_raw_strict(cf_raw) is None)
  assert_true(
    @kgc.SignMasterPublicKey::from_bytes_uncompressed_strict(cf_unc) is None,
  )
  assert_true(@kgc.EncUserPrivateKey::from_bytes_raw_strict(cf_raw) is None)
  assert_true(
    @kgc.EncUserPrivateKey::from_bytes_uncompressed_strict(cf_unc) is None,
  )
  // 7. Infinity points injected directly into every protocol entry point are rejected
  let g1_inf = @ec.G1Affine::identity()
  let g2_inf = @ec.G2Affine::identity()
  let r_one = @field.Fn::one()
  let sign_master = @sm9.sign_master_from_seed(b"adv-sign")
  let p_pub_s = sign_master.public_key()
  let ds_a = match @sm9.extract_sign_key(sign_master, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let valid_sig = match @sm9.sign(p_pub_s, ds_a, b"hello") {
    Ok(s) => s
    Err(e) => abort(e)
  }
  assert_true(
    @sign.sign_with_r(g2_inf, ds_a.to_g1(), b"hello", r_one) is Err(_),
  )
  assert_true(
    @sign.sign_with_r(p_pub_s.to_g2(), g1_inf, b"hello", r_one) is Err(_),
  )
  assert_true(!@sign.verify(g2_inf, b"Alice", b"hello", valid_sig))
  let enc_master = @sm9.enc_master_from_seed(b"adv-enc")
  let p_pub_e = enc_master.public_key()
  let de_a = match @sm9.extract_keyex_key(enc_master, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let de_b = match @sm9.extract_enc_key(enc_master, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  assert_true(@keyex.generate_ephemeral(g1_inf, b"Bob", r_one) is Err(_))
  assert_true(
    @keyex.responder_exchange(
      g1_inf,
      b"Alice",
      b"Bob",
      de_b.to_g2(),
      r_one,
      p1,
      p1,
      16,
    )
    is Err(_),
  )
  assert_true(
    @keyex.responder_exchange(
      p_pub_e.to_g1(),
      b"Alice",
      b"Bob",
      g2_inf,
      r_one,
      p1,
      p1,
      16,
    )
    is Err(_),
  )
  assert_true(
    @sm9.keyex_responder(p_pub_e, b"Alice", b"Bob", de_b, r_one, g1_inf, p1, 16)
    is Err(_),
  )
  assert_true(
    @sm9.keyex_initiator(p_pub_e, b"Alice", b"Bob", de_a, r_one, p1, g1_inf, 16)
    is Err(_),
  )
  assert_true(@enc.kem_encapsulate_with_r(g1_inf, b"Bob", 32, r_one) is Err(_))
  assert_true(@sm9.kem_decapsulate(b"Bob", de_b, g1_inf, 32) is Err(_))
  assert_true(@enc.kem_decapsulate(b"Bob", g2_inf, p1, 32) is Err(_))
  assert_true(@enc.encrypt_with_r(g1_inf, b"Bob", b"msg", r_one) is Err(_))
  // Ciphertext embedding malformed C1 (off-curve, >=p, all-zero) rejected by decrypt
  let adv_ent = @sm9.sm3_hash(b"adv-bad-c1-entropy")
  let valid_ct = match @sm9.encrypt(p_pub_e, b"Bob", b"msg", adv_ent) {
    Ok(c) => c
    Err(e) => abort(e)
  }
  let bad_c1_samples : FixedArray[Bytes] = [off_g1_raw, ge_p_g1, zero64]
  for i = 0; i < bad_c1_samples.length(); i = i + 1 {
    let bad_c1 = bad_c1_samples[i]
    let forged_ct = Bytes::makei(valid_ct.length(), fn(j) {
      if j < 64 {
        bad_c1[j]
      } else {
        valid_ct[j]
      }
    })
    assert_true(
      @sm9.decrypt(b"Bob", de_b, forged_ct, mode=@enc.EncMode::KdfXor) is Err(_),
    )
    assert_true(
      @sm9.decrypt(b"Bob", de_b, forged_ct, mode=@enc.EncMode::Sm4EcbPkcs7)
      is Err(_),
    )
  }
}

///|
test "Adversarial forgery & tampering: signatures, key exchange confirmations, and ciphertexts" {
  // === 1. Signature forgery tests ===
  let sign_m1 = @sm9.sign_master_from_seed(b"forge-sign-m1")
  let sign_m2 = @sm9.sign_master_from_seed(b"forge-sign-m2")
  let p_pub_s1 = sign_m1.public_key()
  let p_pub_s2 = sign_m2.public_key()
  let ds_alice = match @sm9.extract_sign_key(sign_m1, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let msg = b"Transfer 1000 units"
  let sig = match @sm9.sign(p_pub_s1, ds_alice, msg) {
    Ok(s) => s
    Err(e) => abort(e)
  }
  assert_true(@sm9.verify(p_pub_s1, b"Alice", msg, sig))
  // 1a. Flip 1 bit in h
  let sig_raw = sig.to_bytes_raw()
  let bad_h_raw = flip_bit(sig_raw, 31, b'\x01')
  match @sign.Signature::from_bytes_raw_strict(bad_h_raw) {
    Some(forged) => assert_true(!@sm9.verify(p_pub_s1, b"Alice", msg, forged))
    None => ()
  }
  // 1b. Flip 1 bit in S (off-curve) AND valid shifted point S + P1 (on-curve forgery)
  let bad_s_raw = flip_bit(sig_raw, 95, b'\x01')
  assert_true(@sign.Signature::from_bytes_raw_strict(bad_s_raw) is None)
  let shifted_s = sig
    .s()
    .to_jac()
    .add_mixed(@ec.G1Affine::generator())
    .to_affine()
  let forged_s_sig = match @sign.Signature::new_checked(sig.h(), shifted_s) {
    Some(s) => s
    None => abort("shifted S should be a valid G1 point")
  }
  assert_true(!@sm9.verify(p_pub_s1, b"Alice", msg, forged_s_sig))
  // 1c. h == 0 and h >= N strictly rejected
  assert_true(@sign.Signature::new_checked(@field.Fn::zero(), sig.s()) is None)
  let zero_h_raw = Bytes::makei(96, fn(i) {
    if i < 32 {
      b'\x00'
    } else {
      sig_raw[i]
    }
  })
  assert_true(@sign.Signature::from_bytes_raw_strict(zero_h_raw) is None)
  let n_bytes = @field.order_n.to_be_bytes()
  let ge_n_raw = Bytes::makei(96, fn(i) {
    if i < 32 {
      n_bytes[i]
    } else {
      sig_raw[i]
    }
  })
  assert_true(@sign.Signature::from_bytes_raw_strict(ge_n_raw) is None)
  // 1d. Cross-identity, cross-hid, cross-master-key, tampered message
  assert_true(!@sm9.verify(p_pub_s1, b"Bob", msg, sig))
  assert_true(!@sm9.verify(p_pub_s1, b"Alice", msg, sig, hid=@sm9.HID_KEYEX))
  assert_true(!@sm9.verify(p_pub_s1, b"Alice", msg, sig, hid=@sm9.HID_ENC))
  assert_true(!@sm9.verify(p_pub_s2, b"Alice", msg, sig))
  assert_true(!@sm9.verify(p_pub_s1, b"Alice", b"Transfer 1001 units", sig))
  // === 2. Key exchange confirmation tampering tests ===
  let enc_m = @sm9.enc_master_from_seed(b"forge-keyex-master")
  let p_pub_e = enc_m.public_key()
  let de_a_kx = match @sm9.extract_keyex_key(enc_m, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let de_b_kx = match @sm9.extract_keyex_key(enc_m, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let r_a = derive_nonzero_scalar(b"forge-kx-ra")
  let r_b = derive_nonzero_scalar(b"forge-kx-rb")
  let ra_pt = match @sm9.keyex_ephemeral(p_pub_e, b"Bob", r_a) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let rb_pt = match @sm9.keyex_ephemeral(p_pub_e, b"Alice", r_b) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let resp = match
    @sm9.keyex_responder(
      p_pub_e, b"Alice", b"Bob", de_b_kx, r_b, ra_pt, rb_pt, 32,
    ) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  // Tamper 1 bit in S_B -> initiator rejects
  let bad_sb = flip_bit(resp.s_b, 0, b'\x80')
  assert_true(
    @sm9.keyex_initiator(
      p_pub_e,
      b"Alice",
      b"Bob",
      de_a_kx,
      r_a,
      ra_pt,
      rb_pt,
      32,
      peer_s_b=bad_sb,
    )
    is Err(_),
  )
  // Valid initiator run, then tamper 1 bit in S_A -> responder confirmation rejects
  let init = match
    @sm9.keyex_initiator(
      p_pub_e,
      b"Alice",
      b"Bob",
      de_a_kx,
      r_a,
      ra_pt,
      rb_pt,
      32,
      peer_s_b=resp.s_b,
    ) {
    Ok(v) => v
    Err(e) => abort(e)
  }
  assert_true(@sm9.keyex_verify_confirmation(resp.s_2, init.s_a))
  let bad_sa = flip_bit(init.s_a, 31, b'\x01')
  assert_true(!@sm9.keyex_verify_confirmation(resp.s_2, bad_sa))
  assert_true(!@sm9.keyex_verify_confirmation(resp.s_2, init.s_a[0:31]))
  // Tampered ephemeral point R_B' = R_B + P1 -> confirmation mismatch
  let rb_forged = rb_pt
    .to_jac()
    .add_mixed(@ec.G1Affine::generator())
    .to_affine()
  assert_true(
    @sm9.keyex_initiator(
      p_pub_e,
      b"Alice",
      b"Bob",
      de_a_kx,
      r_a,
      ra_pt,
      rb_forged,
      32,
      peer_s_b=resp.s_b,
    )
    is Err(_),
  )
  // === 3. Ciphertext tampering & truncation tests (both KdfXor and Sm4EcbPkcs7) ===
  let de_a_enc = match @sm9.extract_enc_key(enc_m, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let de_b_enc = match @sm9.extract_enc_key(enc_m, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let secret = b"Top secret SM9 payload"
  let modes : FixedArray[@enc.EncMode] = [
    @enc.EncMode::KdfXor,
    @enc.EncMode::Sm4EcbPkcs7,
  ]
  for m_idx = 0; m_idx < modes.length(); m_idx = m_idx + 1 {
    let mode = modes[m_idx]
    let ent = Bytes::makei(32, fn(j) {
      ((m_idx * 71 + j + 0x11) & 0xff).to_byte()
    })
    let ct = match @sm9.encrypt(p_pub_e, b"Bob", secret, ent, mode~) {
      Ok(c) => c
      Err(e) => abort(e)
    }
    assert_eq(@sm9.decrypt(b"Bob", de_b_enc, ct, mode~), Ok(secret))
    // 3a. Flip 1 bit in C1 (off-curve)
    assert_true(
      @sm9.decrypt(b"Bob", de_b_enc, flip_bit(ct, 10, b'\x01'), mode~) is Err(_),
    )
    // 3b. Replace C1 with another valid on-curve G1 point (C1 + P1)
    let c1_orig = match @ec.G1Affine::from_bytes_raw_strict(ct[0:64]) {
      Some(pt) => pt
      None => abort("valid ciphertext C1 must parse")
    }
    let c1_alt = c1_orig
      .to_jac()
      .add_mixed(@ec.G1Affine::generator())
      .to_affine()
      .to_bytes_raw()
    let ct_alt_c1 = Bytes::makei(ct.length(), fn(i) {
      if i < 64 {
        c1_alt[i]
      } else {
        ct[i]
      }
    })
    assert_eq(
      @sm9.decrypt(b"Bob", de_b_enc, ct_alt_c1, mode~),
      Err("decryption failed"),
    )
    // 3c. Flip 1 bit in C3 (MAC tag at bytes 64..96)
    assert_eq(
      @sm9.decrypt(b"Bob", de_b_enc, flip_bit(ct, 64, b'\x01'), mode~),
      Err("decryption failed"),
    )
    assert_eq(
      @sm9.decrypt(b"Bob", de_b_enc, flip_bit(ct, 95, b'\x80'), mode~),
      Err("decryption failed"),
    )
    // 3d. Flip 1 bit in C2 (ciphertext body at bytes 96..)
    assert_eq(
      @sm9.decrypt(b"Bob", de_b_enc, flip_bit(ct, 96, b'\x01'), mode~),
      Err("decryption failed"),
    )
    assert_eq(
      @sm9.decrypt(
        b"Bob",
        de_b_enc,
        flip_bit(ct, ct.length() - 1, b'\x01'),
        mode~,
      ),
      Err("decryption failed"),
    )
    // 3e. Truncated ciphertexts & 97-byte IND-CCA2 probe packet
    assert_true(@sm9.decrypt(b"Bob", de_b_enc, b"", mode~) is Err(_))
    assert_true(@sm9.decrypt(b"Bob", de_b_enc, ct[0:63], mode~) is Err(_))
    assert_true(@sm9.decrypt(b"Bob", de_b_enc, ct[0:95], mode~) is Err(_))
    assert_eq(
      @sm9.decrypt(b"Bob", de_b_enc, ct[0:ct.length() - 1], mode~),
      Err("decryption failed"),
    )
    let probe_97 = Bytes::makei(97, fn(i) {
      if i < 64 {
        ct[i]
      } else if i < 96 {
        b'\x00'
      } else {
        b'\xaa'
      }
    })
    assert_eq(
      @sm9.decrypt(b"Bob", de_b_enc, probe_97, mode~),
      Err("decryption failed"),
    )
    // 3f. Wrong recipient ID or wrong user private key
    assert_eq(
      @sm9.decrypt(b"Alice", de_b_enc, ct, mode~),
      Err("decryption failed"),
    )
    assert_eq(
      @sm9.decrypt(b"Bob", de_a_enc, ct, mode~),
      Err("decryption failed"),
    )
    assert_eq(
      @sm9.decrypt(b"Alice", de_a_enc, ct, mode~),
      Err("decryption failed"),
    )
  }
  // Cross-mode decryption strictly rejected with uniform error
  let ct_xor = match
    @sm9.encrypt(
      p_pub_e,
      b"Bob",
      secret,
      @sm9.sm3_hash(b"cross-mode-xor"),
      mode=@enc.EncMode::KdfXor,
    ) {
    Ok(c) => c
    Err(e) => abort(e)
  }
  let ct_sm4 = match
    @sm9.encrypt(
      p_pub_e,
      b"Bob",
      secret,
      @sm9.sm3_hash(b"cross-mode-sm4"),
      mode=@enc.EncMode::Sm4EcbPkcs7,
    ) {
    Ok(c) => c
    Err(e) => abort(e)
  }
  assert_eq(
    @sm9.decrypt(b"Bob", de_b_enc, ct_xor, mode=@enc.EncMode::Sm4EcbPkcs7),
    Err("decryption failed"),
  )
  assert_eq(
    @sm9.decrypt(b"Bob", de_b_enc, ct_sm4, mode=@enc.EncMode::KdfXor),
    Err("decryption failed"),
  )
}
