///|
fn to_hex(data : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i = 0; i < data.length(); i = i + 1 {
    let v = data[i].to_int()
    buf.write_char(digits[(v >> 4) & 0xF].to_int().unsafe_to_char())
    buf.write_char(digits[v & 0xF].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
fn hex_nibble(c : Int32) -> Int32 {
  if c >= 0x30 && c <= 0x39 {
    c - 0x30
  } else if c >= 0x61 && c <= 0x66 {
    c - 0x61 + 10
  } else if c >= 0x41 && c <= 0x46 {
    c - 0x41 + 10
  } else {
    abort("invalid hex character")
  }
}

///|
fn from_hex(s : String) -> Bytes {
  let n = s.length() / 2
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    let hi = hex_nibble(s[i * 2].to_int())
    let lo = hex_nibble(s[i * 2 + 1].to_int())
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn flip_byte(data : Bytes, idx : Int32, mask : UInt32) -> Bytes {
  let out = FixedArray::make(data.length(), b'\x00')
  for i = 0; i < data.length(); i = i + 1 {
    out[i] = data[i]
  }
  out[idx] = (out[idx].to_uint() ^ mask).to_byte()
  Bytes::from_array(out)
}

///|
fn append_bytes(a : Bytes, b : Bytes) -> Bytes {
  let out = FixedArray::make(a.length() + b.length(), b'\x00')
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  for i = 0; i < b.length(); i = i + 1 {
    out[a.length() + i] = b[i]
  }
  Bytes::from_array(out)
}

///|
fn slice_bytes(data : Bytes, start : Int32, end : Int32) -> Bytes {
  let out = FixedArray::make(end - start, b'\x00')
  for i = 0; i < end - start; i = i + 1 {
    out[i] = data[start + i]
  }
  Bytes::from_array(out)
}

///|
test "GB/T 32918.2 official SM2 signature vector on sm2p256v1" {
  let da_bytes = from_hex(
    "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8",
  )
  let priv_key = @sm2.PrivateKey::from_bytes(da_bytes)
  assert_eq(priv_key.to_bytes(), da_bytes)
  let pub_key = priv_key.public_key()
  assert_true(pub_key.is_valid())
  assert_eq(
    to_hex(pub_key.x_bytes()),
    "09f9df311e5421a150dd7d161e4bc5c672179fad1833fc076bb08ff356f35020",
  )
  assert_eq(
    to_hex(pub_key.y_bytes()),
    "ccea490ce26775a52dc6ea718cc1aa600aed05fbf35e084a6632f6072da9ad13",
  )

  let za = @sm2.compute_za(@sm2.DEFAULT_SM2_ID, pub_key)
  assert_eq(
    to_hex(za),
    "b2e14c5c79c6df5b85f4fe7ed8db7a262b9da7e07ccb0ea9f4747b8ccda8a4f3",
  )

  let msg = b"message digest"
  let digest = @sm2.compute_digest(@sm2.DEFAULT_SM2_ID, pub_key, msg)
  assert_eq(
    to_hex(digest),
    "f0b43e94ba45accaace692ed534382eb17e6ab5a19ce7b31f4486fdfc0d28640",
  )

  let k = from_hex(
    "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21",
  )
  let (r, s) = @sm2.sign_with_k(priv_key, @sm2.DEFAULT_SM2_ID, msg, k)
  assert_eq(
    to_hex(r),
    "f5a03b0648d2c4630eeac513e1bb81a15944da3827d5b74143ac7eaceee720b3",
  )
  assert_eq(
    to_hex(s),
    "b1b6aa29df212fd8763182bc0d421ca1bb9038fd1f7f42d4840b69c485bbc1aa",
  )

  // Raw and DER verification
  assert_true(@sm2.verify_raw(pub_key, @sm2.DEFAULT_SM2_ID, msg, r, s))
  let der = @sm2.encode_sig_der(r, s)
  let (r2, s2) = @sm2.decode_sig_der(der)
  assert_eq(r2, r)
  assert_eq(s2, s)
  assert_true(@sm2.verify_der(pub_key, @sm2.DEFAULT_SM2_ID, msg, der))

  // Tampered message / ID / signature rejected
  assert_false(
    @sm2.verify_raw(pub_key, @sm2.DEFAULT_SM2_ID, b"message digesT", r, s),
  )
  assert_false(@sm2.verify_raw(pub_key, b"other-id", msg, r, s))
  assert_false(
    @sm2.verify_raw(pub_key, @sm2.DEFAULT_SM2_ID, msg, flip_byte(r, 0, 1U), s),
  )
  assert_false(
    @sm2.verify_raw(pub_key, @sm2.DEFAULT_SM2_ID, msg, r, flip_byte(s, 31, 1U)),
  )
  assert_false(
    @sm2.verify_der(
      pub_key,
      @sm2.DEFAULT_SM2_ID,
      msg,
      append_bytes(der, b"\x00"),
    ),
  )
  assert_false(
    @sm2.verify_der(
      pub_key,
      @sm2.DEFAULT_SM2_ID,
      msg,
      flip_byte(der, der.length() - 1, 1U),
    ),
  )
}

///|
test "SM2 deterministic signing and DER roundtrip" {
  let sk1 = @sm2.derive_keypair_from_seed(b"sm2-signing-seed-alpha")
  let sk2 = @sm2.derive_keypair_from_seed(b"sm2-signing-seed-beta")
  let pk1 = sk1.public_key()
  let pk2 = sk2.public_key()
  assert_true(pk1 != pk2)

  let msg = b"GM/T 0024-2023 TLCP handshake transcript"
  let (r1, s1) = @sm2.sign_deterministic(sk1, @sm2.DEFAULT_SM2_ID, msg)
  let (r2, s2) = @sm2.sign_deterministic(sk1, @sm2.DEFAULT_SM2_ID, msg)
  assert_eq(r1, r2)
  assert_eq(s1, s2)
  assert_true(@sm2.verify_raw(pk1, @sm2.DEFAULT_SM2_ID, msg, r1, s1))
  assert_false(@sm2.verify_raw(pk2, @sm2.DEFAULT_SM2_ID, msg, r1, s1))

  let der_sig = @sm2.sign_der(sk1, @sm2.DEFAULT_SM2_ID, msg)
  assert_true(@sm2.verify_der(pk1, @sm2.DEFAULT_SM2_ID, msg, der_sig))
  assert_false(@sm2.verify_der(pk2, @sm2.DEFAULT_SM2_ID, msg, der_sig))

  // Empty message signing
  let empty_sig = @sm2.sign_der(sk1, b"", b"")
  assert_true(@sm2.verify_der(pk1, b"", b"", empty_sig))
}

///|
test "SM2 key validation and compressed/uncompressed/raw public key roundtrips" {
  // Boundary private keys: d = 1 gives base point G; d = n - 2 is valid
  let d1 = from_hex(
    "0000000000000000000000000000000000000000000000000000000000000001",
  )
  let sk_one = @sm2.PrivateKey::from_bytes(d1)
  let g_pub = sk_one.public_key()
  assert_eq(
    to_hex(g_pub.x_bytes()),
    "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7",
  )
  assert_eq(
    to_hex(g_pub.y_bytes()),
    "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
  )

  // d = n - 2 must be accepted
  let d_max = from_hex(
    "fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54121",
  )
  let sk_max = @sm2.PrivateKey::from_bytes(d_max)
  assert_true(sk_max.public_key().is_valid())

  // Invalid private keys: 0, n-1, n, all 0xFF, wrong length
  let bad_privs : Array[Bytes] = [
    from_hex("0000000000000000000000000000000000000000000000000000000000000000"),
    from_hex("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54122"),
    from_hex("fffffffeffffffffffffffffffffffff7203df6b21c6052b53bbf40939d54123"),
    from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
    b"short",
  ]
  for i = 0; i < bad_privs.length(); i = i + 1 {
    let ok = try {
      let _ = @sm2.PrivateKey::from_bytes(bad_privs[i])
      true
    } catch {
      _ => false
    }
    assert_false(ok)
  }

  // Empty seed rejected
  let empty_seed_ok = try {
    let _ = @sm2.derive_keypair_from_seed(b"")
    true
  } catch {
    _ => false
  }
  assert_false(empty_seed_ok)

  // Public key roundtrip for both even-Y (G) and odd-Y (test vector PA)
  let keys : Array[@sm2.PublicKey] = [
    g_pub, // even Y (0x...a0 -> 0x02)
    @sm2.PrivateKey::from_bytes(
      from_hex(
        "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8",
      ),
    ).public_key(), // odd Y (0x...13 -> 0x03)
  ]
  assert_eq(keys[0].to_compressed_bytes()[0], b'\x02')
  assert_eq(keys[1].to_compressed_bytes()[0], b'\x03')

  for i = 0; i < keys.length(); i = i + 1 {
    let pk = keys[i]
    let uncomp = pk.to_uncompressed_bytes()
    let xy = pk.to_xy_bytes()
    let comp = pk.to_compressed_bytes()
    assert_eq(uncomp.length(), 65)
    assert_eq(xy.length(), 64)
    assert_eq(comp.length(), 33)
    assert_eq(@sm2.PublicKey::from_bytes(uncomp), pk)
    assert_eq(@sm2.PublicKey::from_bytes(xy), pk)
    assert_eq(@sm2.PublicKey::from_bytes(comp), pk)
  }

  // Reject off-curve point, infinity (all zeros), non-canonical X >= p, bad prefix
  let off_curve = flip_byte(g_pub.to_uncompressed_bytes(), 64, 1U)
  let zeros64 = Bytes::from_array(FixedArray::make(64, b'\x00'))
  let zeros65 = append_bytes(b"\x04", zeros64)
  let bad_prefix = flip_byte(g_pub.to_uncompressed_bytes(), 0, 1U)
  let non_canonical = from_hex(
    "04fffffffeffffffffffffffffffffffffffffffff00000000ffffffffffffffffbc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0",
  )
  let bad_pubs : Array[Bytes] = [
    off_curve, zeros64, zeros65, bad_prefix, non_canonical, b"too-short",
  ]
  for i = 0; i < bad_pubs.length(); i = i + 1 {
    let ok = try {
      let _ = @sm2.PublicKey::from_bytes(bad_pubs[i])
      true
    } catch {
      _ => false
    }
    assert_false(ok)
  }
}

///|
test "GB/T 32918.3 SM2 key exchange protocol on sm2p256v1" {
  let priv_a = @sm2.PrivateKey::from_bytes(
    from_hex("81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029"),
  )
  let eph_priv_a = @sm2.PrivateKey::from_bytes(
    from_hex("d4de15474db74d06491c440d305e012400990f3e390c7e87153c12db2ea60bb3"),
  )
  let priv_b = @sm2.PrivateKey::from_bytes(
    from_hex("785129917d45a9ea5437a59356b82338eaadda6ceb199088f14ae10defa229b5"),
  )
  let eph_priv_b = @sm2.PrivateKey::from_bytes(
    from_hex("7e07124814b309489125eaed101113164ebf0f3458c5bd88335c1f9d596243d6"),
  )
  let id_a = b"ALICE123@YAHOO.COM"
  let id_b = b"BILL456@YAHOO.COM"

  let res_a = @sm2.key_exchange_initiator(
    id_a,
    priv_a,
    eph_priv_a,
    id_b,
    priv_b.public_key(),
    eph_priv_b.public_key(),
    16,
  )
  let res_b = @sm2.key_exchange_responder(
    id_b,
    priv_b,
    eph_priv_b,
    id_a,
    priv_a.public_key(),
    eph_priv_a.public_key(),
    16,
  )

  assert_eq(res_a, res_b)
  assert_eq(to_hex(res_a.shared_key), "3c1362830b075a6f891dbf651997bf50")
  assert_eq(
    to_hex(res_a.s1),
    "2ef96317f3b78f65f5b838dd3500bf720893766b325aa26f9731c37377bd1144",
  )
  assert_eq(
    to_hex(res_a.s2),
    "e8982435be4345c5b53f2b858974234f3bde4ff6a74e98bd355667b353bdb0cf",
  )

  // 48-byte TLCP premaster/master key length agreement
  let res48_a = @sm2.key_exchange_initiator(
    id_a,
    priv_a,
    eph_priv_a,
    id_b,
    priv_b.public_key(),
    eph_priv_b.public_key(),
    48,
  )
  let res48_b = @sm2.key_exchange_responder(
    id_b,
    priv_b,
    eph_priv_b,
    id_a,
    priv_a.public_key(),
    eph_priv_a.public_key(),
    48,
  )
  assert_eq(res48_a, res48_b)
  assert_eq(res48_a.shared_key.length(), 48)

  // Mismatched ID causes confirmation mismatch
  let res_wrong_id = @sm2.key_exchange_responder(
    b"WRONG@ID",
    priv_b,
    eph_priv_b,
    id_a,
    priv_a.public_key(),
    eph_priv_a.public_key(),
    16,
  )
  assert_true(res_wrong_id.shared_key != res_a.shared_key)
  assert_true(res_wrong_id.s1 != res_a.s1)
  assert_true(res_wrong_id.s2 != res_a.s2)

  // Invalid klen <= 0 rejected
  let bad_klen = try {
    let _ = @sm2.key_exchange_initiator(
      id_a,
      priv_a,
      eph_priv_a,
      id_b,
      priv_b.public_key(),
      eph_priv_b.public_key(),
      0,
    )
    true
  } catch {
    _ => false
  }
  assert_false(bad_klen)
}

///|
test "GB/T 32918.4 SM2 encryption/decryption (C1C3C2 and ASN.1 DER SM2Cipher)" {
  let priv_b = @sm2.PrivateKey::from_bytes(
    from_hex("3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"),
  )
  let pub_b = priv_b.public_key()
  let k = from_hex(
    "59276e27d506861a16680f3ad9c02dccef3cc1fa3cdbe4ce6d54b80deac1bc21",
  )
  let pt = b"encryption standard"
  let ct = @sm2.encrypt_with_k(pub_b, pt, k)

  let expected_ct = from_hex(
    "0404ebfc718e8d1798620432268e77feb6415e2ede0e073c0f4f640ecd2e149a73e858f9d81e5430a57b36daab8f950a3c64e6ee6a63094d99283aff767e124df059983c18f809e262923c53aec295d30383b54e39d609d160afcb1908d0bd876621886ca989ca9c7d58087307ca93092d651efa",
  )
  assert_eq(ct, expected_ct)

  // Decrypt 0x04-prefixed C1C3C2
  assert_eq(@sm2.decrypt_c1c3c2(priv_b, ct), pt)

  // Decrypt unprefixed C1C3C2 (note: x1 itself starts with 0x04 — tests disambiguation!)
  let ct_unprefixed = slice_bytes(ct, 1, ct.length())
  assert_eq(ct_unprefixed[0], b'\x04')
  assert_eq(@sm2.decrypt_c1c3c2(priv_b, ct_unprefixed), pt)

  // Seeded C1C3C2 and ASN.1 SM2Cipher roundtrips across empty, 48B TLCP, and 300B (long DER length)
  let long_arr = FixedArray::make(300, b'\x00')
  for i = 0; i < 300; i = i + 1 {
    long_arr[i] = ((i * 37 + 11) & 0xFF).to_byte()
  }
  let plaintexts : Array[Bytes] = [
    b"",
    b"hello SM2!",
    Bytes::from_array(FixedArray::make(48, b'\xA5')),
    Bytes::from_array(long_arr),
  ]
  for i = 0; i < plaintexts.length(); i = i + 1 {
    let m = plaintexts[i]
    let c_raw = @sm2.encrypt_c1c3c2(pub_b, m, b"enc-seed-123456")
    assert_eq(@sm2.decrypt_c1c3c2(priv_b, c_raw), m)

    let c_der = @sm2.encrypt_asn1(pub_b, m, b"enc-seed-123456")
    assert_eq(c_der[0], b'\x30')
    assert_eq(@sm2.decrypt_asn1(priv_b, c_der), m)
  }

  // Tamper C3, C2, C1, wrong key -> all rejected
  let other_sk = @sm2.derive_keypair_from_seed(b"wrong-decrypt-key")
  let tampered_c3 = flip_byte(ct, 65, 0x01U)
  let tampered_c2 = flip_byte(ct, ct.length() - 1, 0x80U)
  let tampered_c1 = flip_byte(ct, 33, 0x01U)
  let bad_c1c3c2 : Array[(@sm2.PrivateKey, Bytes)] = [
    (priv_b, tampered_c3),
    (priv_b, tampered_c2),
    (priv_b, tampered_c1),
    (other_sk, ct),
    (priv_b, slice_bytes(ct, 0, 50)),
  ]
  for i = 0; i < bad_c1c3c2.length(); i = i + 1 {
    let (sk, bad_ct) = bad_c1c3c2[i]
    let ok = try {
      let _ = @sm2.decrypt_c1c3c2(sk, bad_ct)
      true
    } catch {
      _ => false
    }
    assert_false(ok)
  }

  // ASN.1 tamper & malformed DER rejection
  let der_ct = @sm2.encrypt_asn1(pub_b, pt, b"asn1-tamper-seed")
  let bad_der_cases : Array[(@sm2.PrivateKey, Bytes)] = [
    (priv_b, flip_byte(der_ct, der_ct.length() - 1, 0x01U)), // tampered C2
    (priv_b, flip_byte(der_ct, der_ct.length() - pt.length() - 5, 0x01U)), // tampered C3
    (priv_b, append_bytes(der_ct, b"\x00")), // trailing byte
    (priv_b, slice_bytes(der_ct, 0, der_ct.length() - 1)), // truncated
    (other_sk, der_ct), // wrong key
  ]
  for i = 0; i < bad_der_cases.length(); i = i + 1 {
    let (sk, bad_der) = bad_der_cases[i]
    let ok = try {
      let _ = @sm2.decrypt_asn1(sk, bad_der)
      true
    } catch {
      _ => false
    }
    assert_false(ok)
  }
}

///|
test "SM2 DER signature encoding edge cases and strict validation" {
  // Leading zero bytes stripped; MSB >= 0x80 gets single 0x00 sign pad
  let r_small = from_hex(
    "000000000000000000000000000000000000000000000000000000000000007f",
  )
  let s_high = from_hex(
    "8000000000000000000000000000000000000000000000000000000000000001",
  )
  let der = @sm2.encode_sig_der(r_small, s_high)
  // Expected: 30 26 02 01 7f 02 21 00 80 ... 01
  assert_eq(der[0], b'\x30')
  assert_eq(der[1], b'\x26')
  assert_eq(der[2], b'\x02')
  assert_eq(der[3], b'\x01')
  assert_eq(der[4], b'\x7f')
  assert_eq(der[5], b'\x02')
  assert_eq(der[6], b'\x21')
  assert_eq(der[7], b'\x00')
  assert_eq(der[8], b'\x80')
  let (r_dec, s_dec) = @sm2.decode_sig_der(der)
  assert_eq(r_dec, r_small)
  assert_eq(s_dec, s_high)

  // Strict DER rejections: non-minimal integer 0x00 0x7f, negative integer 0x80, non-minimal length 0x81 0x06, indefinite length 0x80
  let bad_ders : Array[Bytes] = [
    from_hex("30070202007f020101"), // redundant leading 0x00 before 0x7f
    from_hex("3006020180020101"), // negative integer (MSB set without 0x00)
    from_hex("308106020101020101"), // non-minimal long length for 6
    from_hex("30800201010201010000"), // indefinite length
    from_hex("300602010102010100"), // trailing garbage
  ]
  for i = 0; i < bad_ders.length(); i = i + 1 {
    let ok = try {
      let _ = @sm2.decode_sig_der(bad_ders[i])
      true
    } catch {
      _ => false
    }
    assert_false(ok)
  }
}
