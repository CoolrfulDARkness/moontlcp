///|
fn to_hex(data : Bytes) -> String {
  let digits = "0123456789abcdef"
  let sb = StringBuilder()
  for i = 0; i < data.length(); i = i + 1 {
    let v = data[i].to_int()
    sb.write_char(digits[(v >> 4) & 0xf].to_int().unsafe_to_char())
    sb.write_char(digits[v & 0xf].to_int().unsafe_to_char())
  }
  sb.to_string()
}

///|
fn bytes_from_ints(arr : Array[Int32]) -> Bytes {
  let out : FixedArray[Byte] = FixedArray::make(arr.length(), b'\x00')
  for i = 0; i < arr.length(); i = i + 1 {
    out[i] = arr[i].to_byte()
  }
  Bytes::from_array(out)
}

///|
fn[T] catch_err(f : () -> T raise @der.DerError) -> @der.DerError? {
  try {
    ignore(f())
    None
  } catch {
    e => Some(e)
  }
}

///|
test "all GM and X.509 OIDs byte-level exact DER encoding and decoding" {
  let vectors : Array[(String, String)] = [
    (@der.OID_EC_PUBLIC_KEY, "06072a8648ce3d0201"),
    (@der.OID_SM2_CURVE, "06082a811ccf5501822d"),
    (@der.OID_SM2_SIGN_SM3, "06082a811ccf55018375"),
    (@der.OID_SM3, "06082a811ccf55018311"),
    (@der.OID_COMMON_NAME, "0603550403"),
    (@der.OID_ORGANIZATION, "060355040a"),
    (@der.OID_COUNTRY, "0603550406"),
    (@der.OID_KEY_USAGE, "0603551d0f"),
    (@der.OID_BASIC_CONSTRAINTS, "0603551d13"),
    (@der.OID_EXT_KEY_USAGE, "0603551d25"),
    (@der.OID_SUBJECT_KEY_ID, "0603551d0e"),
    (@der.OID_AUTHORITY_KEY_ID, "0603551d23"),
    ("2.999.3", "0603883703"),
    ("0.0", "060100"),
  ]
  for i = 0; i < vectors.length(); i = i + 1 {
    let (oid, expected_hex) = vectors[i]
    let w = @der.DerWriter::new()
    w.write_oid(oid)
    let encoded = w.to_bytes()
    assert_eq(to_hex(encoded), expected_hex)
    let r = @der.DerReader::new(encoded[:])
    assert_eq(r.read_oid(), oid)
    r.expect_end()
  }
}

///|
test "all universal tags round-trip including nested SEQUENCE, SET, and context explicit" {
  let w = @der.DerWriter::new()
  w.write_sequence(seq => {
    // [0] EXPLICIT version = v3 (2)
    seq.write_context_explicit(0, ctx => ctx.write_int_u64(2UL))
    // BOOLEAN true and false
    seq.write_boolean(true)
    seq.write_boolean(false)
    // INTEGER edge values
    seq.write_int_u64(0UL)
    seq.write_int_u64(127UL)
    seq.write_int_u64(128UL)
    seq.write_int_u64(0xFFFF_FFFF_FFFF_FFFFUL)
    // 32-byte SM2 unsigned coordinate with MSB=1
    let sm2_x = bytes_from_ints([
      0x85, 0x42, 0xd6, 0x9e, 0x4c, 0x04, 0x4f, 0x18, 0xe8, 0xb9, 0x24, 0x35, 0xbf,
      0x6f, 0xf7, 0xde, 0x45, 0x72, 0x83, 0x91, 0x5c, 0x45, 0x51, 0x7d, 0x72, 0x2e,
      0xdb, 0x8b, 0x08, 0xf1, 0xdf, 0xc3,
    ])
    seq.write_uint_bytes(sm2_x[:])
    // NULL
    seq.write_null()
    // OCTET STRING
    seq.write_octet_string(b"\xde\xad\xbe\xef"[:])
    // BIT STRING (unused=0, unused=7 KeyUsage, empty)
    seq.write_bit_string(b"\x04\x11\x22\x33"[:])
    seq.write_bit_string(b"\x80"[:], unused_bits=7)
    seq.write_bit_string(b""[:], unused_bits=0)
    // OID
    seq.write_oid(@der.OID_SM2_SIGN_SM3)
    // SET containing DN-style strings and times
    seq.write_set(set => {
      set.write_utf8_string("国密SM2双证书CA")
      set.write_printable_string("CN")
      set.write_tlv(@der.TAG_IA5_STRING, b"gm@example.cn"[:])
      set.write_utc_time("261126000000Z")
      set.write_tlv(@der.TAG_GENERALIZED_TIME, b"20261126000000Z"[:])
    })
    // [3] EXPLICIT extensions
    seq.write_context_explicit(3, ext => {
      ext.write_octet_string(b"ext-payload"[:])
    })
  })
  let der = w.to_bytes()
  let outer = @der.DerReader::new(der[:])
  assert_eq(outer.peek_tag(), Some(@der.TAG_SEQUENCE))
  assert_eq(outer.remaining(), der.length())
  let (tag, seq_body, full_tlv) = outer.read_tlv_with_raw()
  assert_eq(tag, @der.TAG_SEQUENCE)
  assert_eq(full_tlv.to_owned(), der)
  assert_true(outer.is_empty())
  outer.expect_end()

  let r = @der.DerReader::new(seq_body)
  // Optional [0] present
  let v_ctx = r.read_optional_context(0)
  guard v_ctx is Some(v_bytes) else { fail("expected [0]") }
  let vr = @der.DerReader::new(v_bytes)
  assert_eq(vr.read_int_u64(), 2UL)
  vr.expect_end()
  // Optional [1] absent
  assert_eq(r.read_optional_context(1), None)
  // Booleans
  assert_eq(r.read_boolean(), true)
  assert_eq(r.read_boolean(), false)
  // Integers
  assert_eq(r.read_int_u64(), 0UL)
  assert_eq(r.read_int_u64(), 127UL)
  assert_eq(r.read_int_u64(), 128UL)
  assert_eq(r.read_int_u64(), 0xFFFF_FFFF_FFFF_FFFFUL)
  let x_out = r.read_uint_bytes()
  assert_eq(x_out.length(), 32)
  assert_eq(x_out[0], b'\x85')
  assert_eq(x_out[31], b'\xc3')
  // NULL
  r.read_null()
  // OCTET STRING
  assert_eq(r.read_octet_string().to_owned(), b"\xde\xad\xbe\xef")
  // BIT STRINGs
  let (bs1, u1) = r.read_bit_string()
  assert_eq(bs1.to_owned(), b"\x04\x11\x22\x33")
  assert_eq(u1, 0)
  let (bs2, u2) = r.read_bit_string()
  assert_eq(bs2.to_owned(), b"\x80")
  assert_eq(u2, 7)
  let (bs3, u3) = r.read_bit_string()
  assert_eq(bs3.length(), 0)
  assert_eq(u3, 0)
  // OID
  assert_eq(r.read_oid(), @der.OID_SM2_SIGN_SM3)
  // SET with all string/time tags
  let set_body = r.expect_tag(@der.TAG_SET)
  let sr = @der.DerReader::new(set_body)
  assert_eq(sr.peek_tag(), Some(@der.TAG_UTF8_STRING))
  assert_eq(sr.read_string(), "国密SM2双证书CA")
  assert_eq(sr.peek_tag(), Some(@der.TAG_PRINTABLE_STRING))
  assert_eq(sr.read_string(), "CN")
  assert_eq(sr.peek_tag(), Some(@der.TAG_IA5_STRING))
  assert_eq(sr.read_string(), "gm@example.cn")
  assert_eq(sr.peek_tag(), Some(@der.TAG_UTC_TIME))
  assert_eq(sr.read_string(), "261126000000Z")
  assert_eq(sr.peek_tag(), Some(@der.TAG_GENERALIZED_TIME))
  assert_eq(sr.read_string(), "20261126000000Z")
  sr.expect_end()
  // Optional [3] present
  let ext_ctx = r.read_optional_context(3)
  guard ext_ctx is Some(ext_bytes) else { fail("expected [3]") }
  let er = @der.DerReader::new(ext_bytes)
  assert_eq(er.read_octet_string().to_owned(), b"ext-payload")
  er.expect_end()
  r.expect_end()
}

///|
test "canonical length encoding across short, 1-byte, 2-byte, and 3-byte boundaries" {
  let sizes : Array[Int32] = [0, 1, 127, 128, 255, 256, 300, 65536]
  for i = 0; i < sizes.length(); i = i + 1 {
    let n = sizes[i]
    let payload = Bytes::from_array(FixedArray::make(n, b'\xab'))
    let w = @der.DerWriter::new()
    w.write_octet_string(payload[:])
    let der = w.to_bytes()
    if n < 128 {
      assert_eq(der.length(), 2 + n)
      assert_eq(der[1].to_int(), n)
    } else if n <= 255 {
      assert_eq(der.length(), 3 + n)
      assert_eq(der[1], b'\x81')
      assert_eq(der[2].to_int(), n)
    } else if n <= 65535 {
      assert_eq(der.length(), 4 + n)
      assert_eq(der[1], b'\x82')
    } else {
      assert_eq(der.length(), 5 + n)
      assert_eq(der[1], b'\x83')
    }
    let r = @der.DerReader::new(der[:])
    let out = r.read_octet_string()
    assert_eq(out.length(), n)
    r.expect_end()
  }
}

///|
test "write_uint_bytes canonicalizes leading zeros and sign bit" {
  let w = @der.DerWriter::new()
  w.write_uint_bytes(b""[:])
  w.write_uint_bytes(b"\x00\x00\x00"[:])
  w.write_uint_bytes(b"\x00\x00\x7f"[:])
  w.write_uint_bytes(b"\x00\x00\x80"[:])
  w.write_uint_bytes(b"\xff"[:])
  assert_eq(to_hex(w.to_bytes()), "02010002010002017f02020080020200ff")
}

///|
test "strict DER rejects non-canonical lengths, indefinite length, overflow, EOF, invalid tags, trailing data" {
  // Indefinite length: 30 80 00 00
  let r_indef = @der.DerReader::new(b"\x30\x80\x00\x00"[:])
  assert_true(
    catch_err(() => r_indef.read_tlv())
    is Some(@der.DerError::IndefiniteLengthNotAllowed),
  )

  // Long form used for length < 128: 04 81 05 ...
  let r_short_long = @der.DerReader::new(b"\x04\x81\x05hello"[:])
  assert_true(
    catch_err(() => r_short_long.read_tlv())
    is Some(@der.DerError::NonCanonicalLength),
  )

  // Long form for length 127: 04 81 7f ...
  let buf127 = Array::make(130, b'\x00')
  buf127[0] = b'\x04'
  buf127[1] = b'\x81'
  buf127[2] = b'\x7f'
  let r127 = @der.DerReader::new(Bytes::from_array(buf127)[:])
  assert_true(
    catch_err(() => r127.read_tlv()) is Some(@der.DerError::NonCanonicalLength),
  )

  // Leading zero in length octets: 04 81 00 and 04 82 00 80 ...
  let r_lz1 = @der.DerReader::new(b"\x04\x81\x00"[:])
  assert_true(
    catch_err(() => r_lz1.read_tlv()) is Some(@der.DerError::NonCanonicalLength),
  )

  let buf_lz2 = Array::make(132, b'\x00')
  buf_lz2[0] = b'\x04'
  buf_lz2[1] = b'\x82'
  buf_lz2[2] = b'\x00'
  buf_lz2[3] = b'\x80'
  let r_lz2 = @der.DerReader::new(Bytes::from_array(buf_lz2)[:])
  assert_true(
    catch_err(() => r_lz2.read_tlv()) is Some(@der.DerError::NonCanonicalLength),
  )

  // Length overflow: 5 length octets, 0xFF reserved, 4 octets >= 2^31
  let r_ovf1 = @der.DerReader::new(b"\x04\x85\x01\x00\x00\x00\x00"[:])
  assert_true(
    catch_err(() => r_ovf1.read_tlv()) is Some(@der.DerError::LengthOverflow),
  )

  let r_ovf2 = @der.DerReader::new(b"\x04\xff\x00"[:])
  assert_true(
    catch_err(() => r_ovf2.read_tlv()) is Some(@der.DerError::LengthOverflow),
  )

  let r_ovf3 = @der.DerReader::new(b"\x04\x84\x80\x00\x00\x00"[:])
  assert_true(
    catch_err(() => r_ovf3.read_tlv()) is Some(@der.DerError::LengthOverflow),
  )

  // Unexpected EOF cases
  let eof_cases : Array[Bytes] = [b"", b"\x04", b"\x04\x05abc", b"\x04\x82\x01"]
  for i = 0; i < eof_cases.length(); i = i + 1 {
    let r = @der.DerReader::new(eof_cases[i][:])
    assert_true(
      catch_err(() => r.read_tlv()) is Some(@der.DerError::UnexpectedEof),
    )
  }

  // Invalid tags: EOC 0x00 and high-tag-number 0x1F
  let r_eoc = @der.DerReader::new(b"\x00\x00"[:])
  assert_true(
    catch_err(() => r_eoc.read_tlv())
    is Some(@der.DerError::InvalidTag(b'\x00')),
  )

  let r_high = @der.DerReader::new(b"\x1f\x20\x00"[:])
  assert_true(
    catch_err(() => r_high.read_tlv())
    is Some(@der.DerError::InvalidTag(b'\x1f')),
  )

  // expect_tag mismatch does not advance cursor
  let r_mis = @der.DerReader::new(b"\x02\x01\x05"[:])
  assert_true(
    catch_err(() => r_mis.expect_tag(@der.TAG_SEQUENCE))
    is Some(@der.DerError::InvalidTag(b'\x02')),
  )
  assert_eq(r_mis.remaining(), 3)
  assert_eq(r_mis.read_int_u64(), 5UL)

  // Trailing data rejected by expect_end
  let r_trail = @der.DerReader::new(b"\x05\x00\x00"[:])
  r_trail.read_null()
  assert_true(
    catch_err(() => r_trail.expect_end()) is Some(@der.DerError::TrailingData),
  )
}

///|
test "strict DER rejects non-minimal integers, negative integers, non-canonical booleans, and invalid bit strings" {
  // Invalid integers
  let bad_ints : Array[Bytes] = [
    b"\x02\x00", // empty
     b"\x02\x01\x80", // negative (-128)
     b"\x02\x02\xff\x01", // negative
     b"\x02\x02\x00\x00", // redundant leading 0x00
     b"\x02\x02\x00\x7f", // redundant leading 0x00
     b"\x02\x03\x00\x00\x80", // redundant leading 0x00
  ]
  for i = 0; i < bad_ints.length(); i = i + 1 {
    let r = @der.DerReader::new(bad_ints[i][:])
    assert_true(
      catch_err(() => r.read_uint_bytes())
      is Some(@der.DerError::InvalidInteger),
    )
  }
  // 9-byte unsigned integer overflows read_int_u64
  let r_u64_ovf = @der.DerReader::new(
    b"\x02\x09\x01\x00\x00\x00\x00\x00\x00\x00\x00"[:],
  )
  assert_true(
    catch_err(() => r_u64_ovf.read_int_u64())
    is Some(@der.DerError::InvalidInteger),
  )

  // Non-canonical BOOLEAN (0x01, 0x7f, wrong length) and non-empty NULL
  let bad_bools : Array[Bytes] = [
    b"\x01\x01\x01", b"\x01\x01\x7f", b"\x01\x00", b"\x01\x02\xff\xff",
  ]
  for i = 0; i < bad_bools.length(); i = i + 1 {
    let r = @der.DerReader::new(bad_bools[i][:])
    assert_true(
      catch_err(() => r.read_boolean())
      is Some(@der.DerError::NonCanonicalLength),
    )
  }
  let r_bad_null = @der.DerReader::new(b"\x05\x01\x00"[:])
  assert_true(
    catch_err(() => r_bad_null.read_null())
    is Some(@der.DerError::NonCanonicalLength),
  )

  // Invalid BIT STRINGs on read
  let bad_bits : Array[Bytes] = [
    b"\x03\x00", // missing unused-bits octet
     b"\x03\x02\x08\x00", // unused_bits == 8 > 7
     b"\x03\x02\xff\x00", // unused_bits == 255
     b"\x03\x01\x01", // empty payload with unused_bits != 0
     b"\x03\x02\x01\x01", // 1 unused bit is non-zero
     b"\x03\x02\x07\x81", // bit 0 set when 7 bits unused
     b"\x03\x02\x03\xff", // lower 3 bits non-zero
  ]
  for i = 0; i < bad_bits.length(); i = i + 1 {
    let r = @der.DerReader::new(bad_bits[i][:])
    assert_true(
      catch_err(() => r.read_bit_string())
      is Some(@der.DerError::InvalidBitString),
    )
  }

  // Invalid BIT STRINGs on write
  let w = @der.DerWriter::new()
  assert_true(
    catch_err(() => w.write_bit_string(b"\x80"[:], unused_bits=8))
    is Some(@der.DerError::InvalidBitString),
  )
  assert_true(
    catch_err(() => w.write_bit_string(b""[:], unused_bits=1))
    is Some(@der.DerError::InvalidBitString),
  )
  assert_true(
    catch_err(() => w.write_bit_string(b"\x81"[:], unused_bits=1))
    is Some(@der.DerError::InvalidBitString),
  )
}

///|
test "strict DER rejects malformed OIDs and invalid strings" {
  // Read invalid OIDs: empty, leading 0x80 non-canonical VLQ, truncated VLQ
  let bad_oid_bytes : Array[Bytes] = [
    b"\x06\x00", b"\x06\x03\x2a\x80\x01", b"\x06\x02\x2a\x81", b"\x06\x01\x80",
  ]
  for i = 0; i < bad_oid_bytes.length(); i = i + 1 {
    let r = @der.DerReader::new(bad_oid_bytes[i][:])
    assert_true(
      catch_err(() => r.read_oid()) is Some(@der.DerError::InvalidOid),
    )
  }

  // Write invalid OIDs
  let bad_oids : Array[String] = [
    "", "1", "3.1", "0.40", "1.40", "1.02.3", "1.2.", ".1.2", "1..2", "1.a.2",
  ]
  for i = 0; i < bad_oids.length(); i = i + 1 {
    let w = @der.DerWriter::new()
    assert_true(
      catch_err(() => w.write_oid(bad_oids[i]))
      is Some(@der.DerError::InvalidOid),
    )
  }

  // Reject overlong UTF-8 (0xC0 0xAF) and surrogate UTF-8 (0xED 0xA0 0x80)
  let r_u1 = @der.DerReader::new(b"\x0c\x02\xc0\xaf"[:])
  assert_true(
    catch_err(() => r_u1.read_string())
    is Some(@der.DerError::InvalidTag(b'\x0c')),
  )

  let r_u2 = @der.DerReader::new(b"\x0c\x03\xed\xa0\x80"[:])
  assert_true(
    catch_err(() => r_u2.read_string())
    is Some(@der.DerError::InvalidTag(b'\x0c')),
  )

  // Reject invalid PrintableString and UTCTime on write
  let w = @der.DerWriter::new()
  assert_true(
    catch_err(() => w.write_printable_string("bad@email"))
    is Some(@der.DerError::InvalidTag(b'\x13')),
  )
  assert_true(
    catch_err(() => w.write_utc_time("261301000000Z"))
    is Some(@der.DerError::InvalidTag(b'\x17')),
  )
}

///|
test "PEM multi-certificate round-trip, 64-char line wrapping, and strict error handling" {
  // Build 3 realistic DER payloads of varying sizes (including >48B to span multiple 64-char lines)
  let cert_sign = Bytes::from_array(
    FixedArray::makei(130, i => ((i * 37 + 11) & 0xff).to_byte()),
  )
  let cert_enc = Bytes::from_array(
    FixedArray::makei(73, i => ((i * 53 + 7) & 0xff).to_byte()),
  )
  let cert_ca = Bytes::from_array(FixedArray::makei(1, _ => b'\x30'))
  let pem1 = @der.pem_encode("CERTIFICATE", cert_sign)
  let pem2 = @der.pem_encode("CERTIFICATE", cert_enc)
  let pem3 = @der.pem_encode("SM2 CA CERTIFICATE", cert_ca)

  // Verify 64-char line wrapping on pem1
  let mut line_len = 0
  let mut in_body = false
  let mut line_idx = 0
  for i = 0; i < pem1.length(); i = i + 1 {
    if pem1[i].to_int() == 0x0a {
      if in_body && line_len > 0 {
        assert_true(line_len <= 64)
      }
      if line_idx == 0 {
        in_body = true
      }
      line_idx = line_idx + 1
      line_len = 0
    } else {
      line_len = line_len + 1
    }
  }

  // Combine with explanatory comments (including UTF-8 Chinese text) and CRLF endings
  let chain = "# 国密 TLCP 双证书链\r\n" +
    pem1 +
    "\r\nSubject: CN=EncCert\r\n" +
    pem2 +
    "\n" +
    pem3
  let decoded = @der.pem_decode_all(chain)
  assert_eq(decoded.length(), 3)
  assert_eq(decoded[0].label, "CERTIFICATE")
  assert_eq(decoded[0].data, cert_sign)
  assert_eq(decoded[1].label, "CERTIFICATE")
  assert_eq(decoded[1].data, cert_enc)
  assert_eq(decoded[2].label, "SM2 CA CERTIFICATE")
  assert_eq(decoded[2].data, cert_ca)

  // Empty data PEM round-trip
  let empty_pem = @der.pem_encode("EMPTY", b"")
  let empty_dec = @der.pem_decode_all(empty_pem)
  assert_eq(empty_dec.length(), 1)
  assert_eq(empty_dec[0].label, "EMPTY")
  assert_eq(empty_dec[0].data, b"")

  // Strict PEM error rejections
  let bad_pems : Array[String] = [
    "-----BEGIN CERTIFICATE-----\nAAAA\n", // unterminated
     "-----BEGIN CERTIFICATE-----\nAAAA\n-----END PRIVATE KEY-----\n", // mismatched label
     "-----BEGIN CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n", // nested BEGIN
     "-----END CERTIFICATE-----\n", // orphan END
     "-----BEGIN -----\nAAAA\n-----END -----\n", // empty label
     "-----BEGIN CERTIFICATE-----\nAAA!\n-----END CERTIFICATE-----\n", // invalid base64 char
     "-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n", // length % 4 != 0
     "-----BEGIN CERTIFICATE-----\nAA==AAAA\n-----END CERTIFICATE-----\n", // padding not at end
     "-----BEGIN CERTIFICATE-----\nAB==\n-----END CERTIFICATE-----\n", // non-zero trailing 4 pad bits
     "-----BEGIN CERTIFICATE-----\nAAB=\n-----END CERTIFICATE-----\n", // non-zero trailing 2 pad bits
  ]
  for i = 0; i < bad_pems.length(); i = i + 1 {
    assert_true(
      catch_err(() => @der.pem_decode_all(bad_pems[i]))
      is Some(@der.DerError::InvalidPem(_)),
    )
  }
}

///|
test "UTF-8 1/2/3/4-byte round-trip, context tag bounds, and GM SM2 SPKI encoding" {
  // 1-byte ASCII, 2-byte Latin (é), 3-byte CJK (国密), 4-byte emoji (🔐)
  let s = "SM2-é-国密-🔐"
  let w = @der.DerWriter::new()
  w.write_utf8_string(s)
  let r = @der.DerReader::new(w.to_bytes()[:])
  assert_eq(r.read_string(), s)
  r.expect_end()

  // Out-of-range context tag numbers rejected
  let w_bad = @der.DerWriter::new()
  assert_true(
    catch_err(() => w_bad.write_context_explicit(31, _ => ()))
    is Some(@der.DerError::InvalidTag(_)),
  )
  let r_empty = @der.DerReader::new(b""[:])
  assert_true(
    catch_err(() => r_empty.read_optional_context(-1))
    is Some(@der.DerError::InvalidTag(_)),
  )

  // Constructed OCTET STRING (0x24) rejected in Strict DER
  let r_cons = @der.DerReader::new(b"\x24\x03\x04\x01\xaa"[:])
  assert_true(
    catch_err(() => r_cons.read_octet_string())
    is Some(@der.DerError::InvalidTag(b'\x24')),
  )

  // GM/T 0015 SM2 SubjectPublicKeyInfo AlgorithmIdentifier exact DER bytes:
  // SEQUENCE { OID id-ecPublicKey, OID sm2p256v1 }
  let spki_alg = @der.DerWriter::new()
  spki_alg.write_sequence(alg => {
    alg.write_oid(@der.OID_EC_PUBLIC_KEY)
    alg.write_oid(@der.OID_SM2_CURVE)
  })
  assert_eq(
    to_hex(spki_alg.to_bytes()),
    "301306072a8648ce3d020106082a811ccf5501822d",
  )
}
