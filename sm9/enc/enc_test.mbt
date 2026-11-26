///|
fn must_hex(hex : String) -> Bytes {
  match @sm3.hex_to_bytes(hex) {
    Some(b) => b
    None => abort("invalid hex literal in test")
  }
}

///|
fn must_fn(hex : String) -> @field.Fn {
  match @field.Fn::from_be_bytes_strict(must_hex(hex)) {
    Some(v) => v
    None => abort("invalid Fn literal in test")
  }
}

///|
fn must_g1_raw(hex : String) -> @ec.G1Affine {
  match @ec.G1Affine::from_bytes_raw_strict(must_hex(hex)) {
    Some(p) => p
    None => abort("invalid G1 literal in test")
  }
}

///|
fn must_g2_raw(hex : String) -> @ec.G2Affine {
  match @ec.G2Affine::from_bytes_raw_strict(must_hex(hex)) {
    Some(q) => q
    None => abort("invalid G2 literal in test")
  }
}

///|
fn flip_byte(data : Bytes, idx : Int32) -> Bytes {
  Bytes::makei(data.length(), fn(i) {
    if i == idx {
      (data[i].to_int() ^ 0x01).to_byte()
    } else {
      data[i]
    }
  })
}

///|
fn official_p_pub_e() -> @ec.G1Affine {
  must_g1_raw(
    "787ed7b8a51f3ab84e0a66003f32da5c720b17eca7137d39abc66e3c80a892ff" +
    "769de61791e5adc4b9ff85a31354900b202871279a8c49dc3f220f644c57a7b1",
  )
}

///|
fn official_de_b() -> @ec.G2Affine {
  must_g2_raw(
    "94736acd2c8c8796cc4785e938301a139a059d3537b6414140b2d31eecf41683" +
    "115bae85f5d8bc6c3dbd9e5342979acccf3c2f4f28420b1cb4f8c0b59a19b158" +
    "7aa5e47570da7600cd760a0cf7beaf71c447f3844753fe74fa7ba92ca7d3b55f" +
    "27538a62e7f7bfb51dce08704796d94c9d56734f119ea44732b50e31cdeb75c1",
  )
}

///|
test "GB/T 38635.4 Appendix A.1: KEM encapsulate and decapsulate byte-exact" {
  let p_pub_e = official_p_pub_e()
  let de_b = official_de_b()
  let id_b = b"Bob"
  let r = must_fn(
    "000074015f8489c01ef4270456f9e6475bfb602bde7f33fd482ab4e3684a6722",
  )
  let expected_c1_hex = "1edee2c3f465914491de44cefb2cb434ab02c308d9dc5e2067b4fed5aaac8a0f" +
    "1c9b4c435eca35ab83bb734174c0f78fde81a53374aff3b3602bbc5e37be9a4c"
  let expected_k_hex = "4ff5cf86d2ad40c8f4bac98d76abdbde0c0e2f0a829d3f911ef5b2bce0695480"

  let out = match @enc.kem_encapsulate_with_r(p_pub_e, id_b, 32, r) {
    Ok(v) => v
    Err(e) => fail("kem_encapsulate_with_r failed: " + e)
  }
  assert_eq(@sm3.bytes_to_hex(out.c1_bytes_raw()), expected_c1_hex)
  assert_eq(
    @sm3.bytes_to_hex(out.c1_bytes_uncompressed()),
    "04" + expected_c1_hex,
  )
  assert_eq(@sm3.bytes_to_hex(out.key()), expected_k_hex)
  assert_eq(out.c1(), must_g1_raw(expected_c1_hex))

  let decap_k = match @enc.kem_decapsulate(id_b, de_b, out.c1(), 32) {
    Ok(k) => k
    Err(e) => fail("kem_decapsulate failed: " + e)
  }
  assert_eq(@sm3.bytes_to_hex(decap_k), expected_k_hex)
  assert_eq(decap_k, out.key())
}

///|
test "GB/T 38635.4 Appendix A.2: KDF-XOR encrypt and decrypt byte-exact" {
  let p_pub_e = official_p_pub_e()
  let de_b = official_de_b()
  let id_b = b"Bob"
  let plaintext = b"Chinese IBE standard"
  let r = must_fn(
    "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )
  let expected_ct_hex = "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff" +
    "42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0" +
    "ba672387bcd6de5016a158a52bb2e7fc429197bcab70b25afee37a2b9db9f367" +
    "1b5f5b0e951489682f3e64e1378cdd5da9513b1c"

  let ct = match
    @enc.encrypt_with_r(p_pub_e, id_b, plaintext, r, mode=@enc.KdfXor) {
    Ok(c) => c
    Err(e) => fail("encrypt_with_r KdfXor failed: " + e)
  }
  assert_eq(ct.length(), 116)
  assert_eq(@sm3.bytes_to_hex(ct), expected_ct_hex)

  let pt = match @enc.decrypt(id_b, de_b, ct, mode=@enc.KdfXor) {
    Ok(p) => p
    Err(e) => fail("decrypt KdfXor failed: " + e)
  }
  assert_eq(pt, plaintext)
}

///|
test "GB/T 38635.4 Appendix A.3: SM4-ECB-PKCS7 encrypt and decrypt byte-exact" {
  let p_pub_e = official_p_pub_e()
  let de_b = official_de_b()
  let id_b = b"Bob"
  let plaintext = b"Chinese IBE standard"
  let r = must_fn(
    "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )
  let expected_ct_hex = "2445471164490618e1ee20528ff1d545b0f14c8bcaa44544f03dab5dac07d8ff" +
    "42ffca97d57cddc05ea405f2e586feb3a6930715532b8000759f13059ed59ac0" +
    "fd3c98dd92c44c68332675a370cceede31e0c5cd209c257601149d12b394a2be" +
    "e05b6fac6f11b965268c994f00dba7a8bb00fd60583546cbdf4649250863f10a"

  let ct = match
    @enc.encrypt_with_r(p_pub_e, id_b, plaintext, r, mode=@enc.Sm4EcbPkcs7) {
    Ok(c) => c
    Err(e) => fail("encrypt_with_r Sm4EcbPkcs7 failed: " + e)
  }
  assert_eq(ct.length(), 128)
  assert_eq(@sm3.bytes_to_hex(ct), expected_ct_hex)

  let pt = match @enc.decrypt(id_b, de_b, ct, mode=@enc.Sm4EcbPkcs7) {
    Ok(p) => p
    Err(e) => fail("decrypt Sm4EcbPkcs7 failed: " + e)
  }
  assert_eq(pt, plaintext)
}

///|
test "deterministic KEM round-trip and domain separation" {
  let p_pub_e = official_p_pub_e()
  let de_b = official_de_b()
  let id_b = b"Bob"
  let seed_a = b"seed-A-0123456789abcdef012345678"
  let seed_b = b"seed-B-0123456789abcdef012345678"

  let out1 = match
    @enc.kem_encapsulate_deterministic(p_pub_e, id_b, 48, seed_a) {
    Ok(v) => v
    Err(e) => fail("kem_encapsulate_deterministic failed: " + e)
  }
  let out2 = match
    @enc.kem_encapsulate_deterministic(p_pub_e, id_b, 48, seed_a) {
    Ok(v) => v
    Err(e) => fail("kem_encapsulate_deterministic repeat failed: " + e)
  }
  let out3 = match
    @enc.kem_encapsulate_deterministic(p_pub_e, id_b, 48, seed_b) {
    Ok(v) => v
    Err(e) => fail("kem_encapsulate_deterministic seed-B failed: " + e)
  }
  assert_eq(out1, out2)
  assert_true(out1.c1() != out3.c1())
  assert_true(out1.key() != out3.key())
  assert_eq(out1.key().length(), 48)

  let decap1 = match @enc.kem_decapsulate(id_b, de_b, out1.c1(), 48) {
    Ok(k) => k
    Err(e) => fail("kem_decapsulate failed: " + e)
  }
  assert_eq(decap1, out1.key())

  // Different ID yields a different derived key on decapsulation
  let decap_wrong_id = match
    @enc.kem_decapsulate(b"Alice", de_b, out1.c1(), 48) {
    Ok(k) => k
    Err(e) => fail("kem_decapsulate wrong id unexpected err: " + e)
  }
  assert_true(decap_wrong_id != out1.key())
}

///|
test "boundary plaintexts: empty, 16-byte block boundary, and 137-byte long messages" {
  let p_pub_e = official_p_pub_e()
  let de_b = official_de_b()
  let id_b = b"Bob"
  let empty = b""
  let block16 = b"0123456789abcdef"
  let long_msg = Bytes::makei(137, fn(i) { ((i * 37 + 11) & 0xFF).to_byte() })
  let ent_empty = b"ent-empty-0123456789abcdef012345"
  let ent_16 = b"ent-16----0123456789abcdef012345"
  let ent_long = b"ent-long--0123456789abcdef012345"

  // Empty plaintext: KdfXor (96B) and Sm4EcbPkcs7 (112B)
  let ct_empty_xor = match
    @enc.encrypt_deterministic(
      p_pub_e,
      id_b,
      empty,
      ent_empty,
      mode=@enc.KdfXor,
    ) {
    Ok(c) => c
    Err(e) => fail("empty KdfXor failed: " + e)
  }
  assert_eq(ct_empty_xor.length(), 96)
  assert_eq(@enc.decrypt(id_b, de_b, ct_empty_xor, mode=@enc.KdfXor), Ok(empty))

  let ct_empty_sm4 = match
    @enc.encrypt_deterministic(
      p_pub_e,
      id_b,
      empty,
      ent_empty,
      mode=@enc.Sm4EcbPkcs7,
    ) {
    Ok(c) => c
    Err(e) => fail("empty Sm4EcbPkcs7 failed: " + e)
  }
  assert_eq(ct_empty_sm4.length(), 112)
  assert_eq(
    @enc.decrypt(id_b, de_b, ct_empty_sm4, mode=@enc.Sm4EcbPkcs7),
    Ok(empty),
  )

  // 16-byte block-aligned plaintext in Sm4EcbPkcs7 adds a full 16B padding block (32B C2 -> 128B ct)
  let ct_b16 = match
    @enc.encrypt_deterministic(
      p_pub_e,
      id_b,
      block16,
      ent_16,
      mode=@enc.Sm4EcbPkcs7,
    ) {
    Ok(c) => c
    Err(e) => fail("block16 Sm4EcbPkcs7 failed: " + e)
  }
  assert_eq(ct_b16.length(), 128)
  assert_eq(
    @enc.decrypt(id_b, de_b, ct_b16, mode=@enc.Sm4EcbPkcs7),
    Ok(block16),
  )

  // Long plaintext (137B) in both modes
  let ct_long_xor = match
    @enc.encrypt_deterministic(
      p_pub_e,
      id_b,
      long_msg,
      ent_long,
      mode=@enc.KdfXor,
    ) {
    Ok(c) => c
    Err(e) => fail("long KdfXor failed: " + e)
  }
  assert_eq(ct_long_xor.length(), 96 + 137)
  assert_eq(
    @enc.decrypt(id_b, de_b, ct_long_xor, mode=@enc.KdfXor),
    Ok(long_msg),
  )

  let ct_long_sm4 = match
    @enc.encrypt_deterministic(
      p_pub_e,
      id_b,
      long_msg,
      ent_long,
      mode=@enc.Sm4EcbPkcs7,
    ) {
    Ok(c) => c
    Err(e) => fail("long Sm4EcbPkcs7 failed: " + e)
  }
  assert_eq(ct_long_sm4.length(), 96 + 144)
  assert_eq(
    @enc.decrypt(id_b, de_b, ct_long_sm4, mode=@enc.Sm4EcbPkcs7),
    Ok(long_msg),
  )
}

///|
test "adversarial tampering, truncation, off-curve C1, wrong key/ID, and mode mismatch" {
  let p_pub_e = official_p_pub_e()
  let de_b = official_de_b()
  let id_b = b"Bob"
  let plaintext = b"Chinese IBE standard"
  let r = must_fn(
    "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )

  let ct_xor = match
    @enc.encrypt_with_r(p_pub_e, id_b, plaintext, r, mode=@enc.KdfXor) {
    Ok(c) => c
    Err(e) => fail(e)
  }
  let ct_sm4 = match
    @enc.encrypt_with_r(p_pub_e, id_b, plaintext, r, mode=@enc.Sm4EcbPkcs7) {
    Ok(c) => c
    Err(e) => fail(e)
  }

  // Tamper C1 (byte 0 and byte 63), C3 (byte 64 and byte 95), C2 (byte 96 and last byte)
  assert_true(
    @enc.decrypt(id_b, de_b, flip_byte(ct_xor, 0), mode=@enc.KdfXor) is Err(_),
  )
  assert_true(
    @enc.decrypt(id_b, de_b, flip_byte(ct_xor, 63), mode=@enc.KdfXor) is Err(_),
  )
  assert_true(
    @enc.decrypt(id_b, de_b, flip_byte(ct_xor, 64), mode=@enc.KdfXor) is Err(_),
  )
  assert_true(
    @enc.decrypt(id_b, de_b, flip_byte(ct_xor, 95), mode=@enc.KdfXor) is Err(_),
  )
  assert_true(
    @enc.decrypt(id_b, de_b, flip_byte(ct_xor, 96), mode=@enc.KdfXor) is Err(_),
  )
  assert_true(
    @enc.decrypt(
      id_b,
      de_b,
      flip_byte(ct_xor, ct_xor.length() - 1),
      mode=@enc.KdfXor,
    )
    is Err(_),
  )

  assert_true(
    @enc.decrypt(id_b, de_b, flip_byte(ct_sm4, 0), mode=@enc.Sm4EcbPkcs7)
    is Err(_),
  )
  assert_true(
    @enc.decrypt(id_b, de_b, flip_byte(ct_sm4, 64), mode=@enc.Sm4EcbPkcs7)
    is Err(_),
  )
  assert_true(
    @enc.decrypt(id_b, de_b, flip_byte(ct_sm4, 96), mode=@enc.Sm4EcbPkcs7)
    is Err(_),
  )
  assert_true(
    @enc.decrypt(
      id_b,
      de_b,
      flip_byte(ct_sm4, ct_sm4.length() - 1),
      mode=@enc.Sm4EcbPkcs7,
    )
    is Err(_),
  )

  // Replace C1 with another valid on-curve point P1 -> MAC must fail
  let p1_raw = @ec.G1Affine::generator().to_bytes_raw()
  let ct_swapped_c1 = Bytes::makei(ct_xor.length(), fn(i) {
    if i < 64 {
      p1_raw[i]
    } else {
      ct_xor[i]
    }
  })
  assert_true(
    @enc.decrypt(id_b, de_b, ct_swapped_c1, mode=@enc.KdfXor) is Err(_),
  )

  // Truncated ciphertexts (< 96B)
  assert_true(@enc.decrypt(id_b, de_b, b"", mode=@enc.KdfXor) is Err(_))
  assert_true(
    @enc.decrypt(id_b, de_b, ct_xor[0:64], mode=@enc.KdfXor) is Err(_),
  )
  assert_true(
    @enc.decrypt(id_b, de_b, ct_xor[0:95], mode=@enc.KdfXor) is Err(_),
  )
  assert_true(
    @enc.decrypt(id_b, de_b, ct_sm4[0:95], mode=@enc.Sm4EcbPkcs7) is Err(_),
  )

  // All-zero C1 (infinity), off-curve C1 (x=1, y=1), and out-of-range C1 (all 0xFF)
  let ct_zero_c1 = Bytes::makei(ct_xor.length(), fn(i) {
    if i < 64 {
      b'\x00'
    } else {
      ct_xor[i]
    }
  })
  assert_true(@enc.decrypt(id_b, de_b, ct_zero_c1, mode=@enc.KdfXor) is Err(_))

  let ct_offcurve_c1 = Bytes::makei(ct_xor.length(), fn(i) {
    if i == 31 || i == 63 {
      b'\x01'
    } else if i < 64 {
      b'\x00'
    } else {
      ct_xor[i]
    }
  })
  assert_true(
    @enc.decrypt(id_b, de_b, ct_offcurve_c1, mode=@enc.KdfXor) is Err(_),
  )

  let ct_overflow_c1 = Bytes::makei(ct_xor.length(), fn(i) {
    if i < 64 {
      b'\xFF'
    } else {
      ct_xor[i]
    }
  })
  assert_true(
    @enc.decrypt(id_b, de_b, ct_overflow_c1, mode=@enc.KdfXor) is Err(_),
  )

  // Wrong ID_B
  assert_true(@enc.decrypt(b"Alice", de_b, ct_xor, mode=@enc.KdfXor) is Err(_))
  assert_true(
    @enc.decrypt(b"Alice", de_b, ct_sm4, mode=@enc.Sm4EcbPkcs7) is Err(_),
  )

  // Wrong de_B (valid G2 point P2, and infinity)
  assert_true(
    @enc.decrypt(id_b, @ec.G2Affine::generator(), ct_xor, mode=@enc.KdfXor)
    is Err(_),
  )
  assert_true(
    @enc.decrypt(id_b, @ec.G2Affine::generator(), ct_sm4, mode=@enc.Sm4EcbPkcs7)
    is Err(_),
  )
  assert_true(
    @enc.decrypt(id_b, @ec.G2Affine::identity(), ct_xor, mode=@enc.KdfXor)
    is Err(_),
  )

  // Mode mismatch: A.2 ciphertext decrypted as A.3 and vice versa
  assert_true(@enc.decrypt(id_b, de_b, ct_xor, mode=@enc.Sm4EcbPkcs7) is Err(_))
  assert_true(@enc.decrypt(id_b, de_b, ct_sm4, mode=@enc.KdfXor) is Err(_))

  // Invalid inputs on KEM / encrypt / decapsulate
  assert_true(
    @enc.kem_encapsulate_with_r(@ec.G1Affine::identity(), id_b, 32, r) is Err(_),
  )
  assert_true(
    @enc.kem_encapsulate_with_r(p_pub_e, id_b, 32, @field.Fn::zero()) is Err(_),
  )
  assert_true(@enc.kem_encapsulate_with_r(p_pub_e, id_b, 0, r) is Err(_))
  assert_true(@enc.kem_encapsulate_with_r(p_pub_e, id_b, -1, r) is Err(_))
  let valid_ent = Bytes::make(32, b'\x42')
  assert_true(
    @enc.kem_encapsulate_deterministic(
      @ec.G1Affine::identity(),
      id_b,
      32,
      valid_ent,
    )
    is Err(_),
  )
  assert_true(
    @enc.kem_encapsulate_deterministic(p_pub_e, id_b, 0, valid_ent) is Err(_),
  )
  assert_true(
    @enc.kem_decapsulate(id_b, de_b, @ec.G1Affine::identity(), 32) is Err(_),
  )
  assert_true(
    @enc.kem_decapsulate(
      id_b,
      @ec.G2Affine::identity(),
      @ec.G1Affine::generator(),
      32,
    )
    is Err(_),
  )
  assert_true(
    @enc.kem_decapsulate(id_b, de_b, @ec.G1Affine::generator(), 0) is Err(_),
  )
  assert_true(
    @enc.encrypt_with_r(@ec.G1Affine::identity(), id_b, plaintext, r) is Err(_),
  )
  assert_true(
    @enc.encrypt_with_r(p_pub_e, id_b, plaintext, @field.Fn::zero()) is Err(_),
  )
  assert_true(
    @enc.encrypt_deterministic(
      @ec.G1Affine::identity(),
      id_b,
      plaintext,
      valid_ent,
    )
    is Err(_),
  )
}

///|
test "adversarial security regression: entropy enforcement, klen bounds, and IND-CCA2 oracle" {
  let p_pub_e = official_p_pub_e()
  let de_b = official_de_b()
  let id_b = b"Bob"
  let plaintext = b"Chinese IBE standard"
  let r = must_fn(
    "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )
  assert_eq(@enc.MIN_ENTROPY_LEN, 32)
  assert_eq(@enc.MAX_KDF_LEN, 16_777_216)

  // 1. Empty and short entropy (0B, 16B, 31B) must be rejected by deterministic KEM & PKE
  let ent_err = "entropy must be at least 32 bytes from a CSPRNG"
  let short_entropies : Array[Bytes] = [
    b"",
    Bytes::make(16, b'\x11'),
    Bytes::make(31, b'\x22'),
  ]
  for i = 0; i < short_entropies.length(); i = i + 1 {
    let ent = short_entropies[i]
    assert_eq(
      @enc.kem_encapsulate_deterministic(p_pub_e, id_b, 32, ent),
      Err(ent_err),
    )
    assert_eq(
      @enc.encrypt_deterministic(
        p_pub_e,
        id_b,
        plaintext,
        ent,
        mode=@enc.KdfXor,
      ),
      Err(ent_err),
    )
    assert_eq(
      @enc.encrypt_deterministic(
        p_pub_e,
        id_b,
        plaintext,
        ent,
        mode=@enc.Sm4EcbPkcs7,
      ),
      Err(ent_err),
    )
  }
  let ent32 = Bytes::make(32, b'\x33')
  assert_true(
    @enc.kem_encapsulate_deterministic(p_pub_e, id_b, 32, ent32) is Ok(_),
  )
  assert_true(
    @enc.encrypt_deterministic(
      p_pub_e,
      id_b,
      plaintext,
      ent32,
      mode=@enc.KdfXor,
    )
    is Ok(_),
  )

  // 2. Oversized klen (> MAX_KDF_LEN) must be rejected across KEM APIs
  let over_klen = @enc.MAX_KDF_LEN + 1
  assert_true(
    @enc.kem_encapsulate_with_r(p_pub_e, id_b, over_klen, r) is Err(_),
  )
  assert_true(
    @enc.kem_encapsulate_deterministic(p_pub_e, id_b, over_klen, ent32)
    is Err(_),
  )
  assert_true(
    @enc.kem_decapsulate(id_b, de_b, @ec.G1Affine::generator(), over_klen)
    is Err(_),
  )

  // 3. IND-CCA2 97-byte chosen-ciphertext oracle probe: C1 || 0x00*32 || 0x00
  // Construct BOTH an ID where K1[0] == 0x00 and an ID where K1[0] != 0x00 for the same C1
  // and verify both return the exact same Err("decryption failed").
  let c1 = @ec.G1Affine::generator()
  let c1_raw = c1.to_bytes_raw()
  let probe97 = Bytes::makei(97, fn(i) {
    if i < 64 {
      c1_raw[i]
    } else {
      b'\x00'
    }
  })
  let w = @pairing.pair_coords(de_b.x(), de_b.y(), c1.x(), c1.y())
  let w_bytes = w.to_bytes()
  let mut id_zero : Bytes = b""
  let mut id_nonzero : Bytes = b""
  let mut found_zero = false
  let mut found_nonzero = false
  for n = 0; n < 4096 && !(found_zero && found_nonzero); n = n + 1 {
    let cand_id = Bytes::from_array([
      ((n >> 8) & 0xFF).to_byte(),
      (n & 0xFF).to_byte(),
    ])
    let kdf_in = Bytes::makei(450, fn(i) {
      if i < 64 {
        c1_raw[i]
      } else if i < 448 {
        w_bytes[i - 64]
      } else {
        cand_id[i - 448]
      }
    })
    let k1_byte = @sm3.kdf(kdf_in, 1)[0]
    if k1_byte == b'\x00' && !found_zero {
      id_zero = cand_id
      found_zero = true
    } else if k1_byte != b'\x00' && !found_nonzero {
      id_nonzero = cand_id
      found_nonzero = true
    }
  }
  assert_true(found_zero)
  assert_true(found_nonzero)
  assert_eq(
    @enc.decrypt(id_zero, de_b, probe97, mode=@enc.KdfXor),
    Err("decryption failed"),
  )
  assert_eq(
    @enc.decrypt(id_nonzero, de_b, probe97, mode=@enc.KdfXor),
    Err("decryption failed"),
  )
  assert_eq(
    @enc.decrypt(id_b, de_b, probe97, mode=@enc.KdfXor),
    Err("decryption failed"),
  )
  // Malformed C2 length for Sm4EcbPkcs7 (0B and 1B, not a non-zero multiple of 16)
  // is rejected uniformly before pairing
  assert_eq(
    @enc.decrypt(id_b, de_b, probe97[0:96], mode=@enc.Sm4EcbPkcs7),
    Err("decryption failed"),
  )
  assert_eq(
    @enc.decrypt(id_b, de_b, probe97, mode=@enc.Sm4EcbPkcs7),
    Err("decryption failed"),
  )
}
