///|
/// Unit tests for stateless handshake & alert inspection (`inspect_handshake` / `inspect_alert`).

///|
fn make_hs_frame(msg_type : Byte, body : Bytes) -> Bytes {
  let len = body.length()
  let out = FixedArray::make(4 + len, b'\x00')
  out[0] = msg_type
  out[1] = ((len >> 16) & 0xFF).to_byte()
  out[2] = ((len >> 8) & 0xFF).to_byte()
  out[3] = (len & 0xFF).to_byte()
  for i = 0; i < len; i = i + 1 {
    out[4 + i] = body[i]
  }
  Bytes::from_array(out)
}

///|
fn join_hs_bytes(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for i = 0; i < parts.length(); i = i + 1 {
    total = total + parts[i].length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut off = 0
  for i = 0; i < parts.length(); i = i + 1 {
    let p = parts[i]
    for j = 0; j < p.length(); j = j + 1 {
      out[off + j] = p[j]
    }
    off = off + p.length()
  }
  Bytes::from_array(out)
}

///|
test "inspect_handshake summarizes all 9 plaintext TLCP handshake message types" {
  let cr = Bytes::make(32, b'\x11')
  let sr = Bytes::make(32, b'\x22')
  let sid = Bytes::make(16, b'\x33')
  // 1. ClientHello (TLCP 1.1 with 4 suites and 16B session ID)
  let ch_wire = @handshake.encode_handshake_msg(
    @handshake.ClientHello({
      version_major: b'\x01',
      version_minor: b'\x01',
      random: cr,
      session_id: sid,
      cipher_suites: [0xE053U, 0xE051U, 0xE013U, 0xE011U],
      compression_methods: b"\x00",
    }),
  )
  let ch_sum = @handshake.inspect_handshake(ch_wire[:])
  assert_eq(ch_sum.msg_type, @handshake.HT_CLIENT_HELLO)
  assert_eq(ch_sum.msg_type_name, "ClientHello")
  assert_eq(ch_sum.body_len, ch_wire.length() - 4)
  assert_eq(ch_sum.total_wire_len, ch_wire.length())
  assert_eq(ch_sum.protocol_version, 0x0101U)
  assert_eq(ch_sum.cipher_suites, [0xE053U, 0xE051U, 0xE013U, 0xE011U])
  assert_eq(ch_sum.selected_suite, None)
  assert_eq(ch_sum.cert_count, 0)
  assert_eq(ch_sum.session_id_len, 16)
  // 1b. ClientHello with non-TLCP version (0x0303) and valid trailing TLV extension
  let ch_ext_body = join_hs_bytes([
    b"\x03\x03", cr, b"\x00", b"\x00\x02\xC0\x2F", b"\x01\x00",
    // Extensions length = 7: type=0x0000 (SNI), len=3, data="abc"
     b"\x00\x07\x00\x00\x00\x03abc",
  ])
  let ch_ext_wire = make_hs_frame(@handshake.HT_CLIENT_HELLO, ch_ext_body)
  let ch_ext_sum = @handshake.inspect_handshake(ch_ext_wire[:])
  assert_eq(ch_ext_sum.protocol_version, 0x0303U)
  assert_eq(ch_ext_sum.cipher_suites, [0xC02FU])
  assert_eq(ch_ext_sum.session_id_len, 0)
  // 2. ServerHello (standard TLCP suite and unknown suite)
  let sh_wire = @handshake.encode_handshake_msg(
    @handshake.ServerHello({
      version_major: b'\x01',
      version_minor: b'\x01',
      random: sr,
      session_id: sid,
      cipher_suite: @handshake.EccSm4GcmSm3,
      compression_method: b'\x00',
    }),
  )
  let sh_sum = @handshake.inspect_handshake(sh_wire[:])
  assert_eq(sh_sum.msg_type, @handshake.HT_SERVER_HELLO)
  assert_eq(sh_sum.msg_type_name, "ServerHello")
  assert_eq(sh_sum.protocol_version, 0x0101U)
  assert_eq(sh_sum.cipher_suites, [])
  assert_eq(sh_sum.selected_suite, Some(0xE053U))
  assert_eq(sh_sum.session_id_len, 16)
  let sh_unknown_body = join_hs_bytes([
    b"\x03\x03", sr, b"\x00", b"\x13\x01\x00", b"\x00\x00",
  ])
  let sh_unknown_sum = @handshake.inspect_handshake(
    make_hs_frame(@handshake.HT_SERVER_HELLO, sh_unknown_body)[:],
  )
  assert_eq(sh_unknown_sum.protocol_version, 0x0303U)
  assert_eq(sh_unknown_sum.selected_suite, Some(0x1301U))
  // 3. Certificate (dual-cert sign + enc list)
  let cert_wire = @handshake.encode_handshake_msg(
    @handshake.Certificate({
      certificates: [Bytes::make(120, b'\x30'), Bytes::make(140, b'\x30')],
    }),
  )
  let cert_sum = @handshake.inspect_handshake(cert_wire[:])
  assert_eq(cert_sum.msg_type, @handshake.HT_CERTIFICATE)
  assert_eq(cert_sum.msg_type_name, "Certificate")
  assert_eq(cert_sum.cert_count, 2)
  assert_eq(cert_sum.total_wire_len, cert_wire.length())
  // 4a/4b. ServerKeyExchange (ECC and ECDHE)
  let ske_ecc_wire = @handshake.encode_handshake_msg(
    @handshake.ServerKeyExchange(
      @handshake.ServerKeyExchange::Ecc(Bytes::make(71, b'\xAA')),
    ),
  )
  let ske_ecc_sum = @handshake.inspect_handshake(ske_ecc_wire[:])
  assert_eq(ske_ecc_sum.msg_type, @handshake.HT_SERVER_KEY_EXCHANGE)
  assert_eq(ske_ecc_sum.msg_type_name, "ServerKeyExchange")
  assert_eq(ske_ecc_sum.total_wire_len, ske_ecc_wire.length())
  let ecdhe_params = @handshake.build_ecdhe_params(
    @handshake.NAMED_CURVE_SM2P256V1,
    Bytes::make(65, b'\x04'),
  )
  let ske_ecdhe_wire = @handshake.encode_handshake_msg(
    @handshake.ServerKeyExchange(
      @handshake.ServerKeyExchange::Ecdhe(
        ecdhe_params,
        Bytes::make(70, b'\xBB'),
      ),
    ),
  )
  let ske_ecdhe_sum = @handshake.inspect_handshake(ske_ecdhe_wire[:])
  assert_eq(ske_ecdhe_sum.msg_type_name, "ServerKeyExchange")
  assert_eq(ske_ecdhe_sum.total_wire_len, ske_ecdhe_wire.length())
  // 5. CertificateRequest
  let cr_wire = @handshake.encode_handshake_msg(
    @handshake.CertificateRequest({
      cert_types: b"\x40\x01",
      ca_names: [Bytes::make(24, b'\x30')],
    }),
  )
  let cr_sum = @handshake.inspect_handshake(cr_wire[:])
  assert_eq(cr_sum.msg_type, @handshake.HT_CERTIFICATE_REQUEST)
  assert_eq(cr_sum.msg_type_name, "CertificateRequest")
  assert_eq(cr_sum.total_wire_len, cr_wire.length())
  // 6. ServerHelloDone
  let shd_wire = @handshake.encode_handshake_msg(@handshake.ServerHelloDone)
  let shd_sum = @handshake.inspect_handshake(shd_wire[:])
  assert_eq(shd_sum.msg_type, @handshake.HT_SERVER_HELLO_DONE)
  assert_eq(shd_sum.msg_type_name, "ServerHelloDone")
  assert_eq(shd_sum.body_len, 0)
  assert_eq(shd_sum.total_wire_len, 4)
  // 7. CertificateVerify
  let cv_wire = @handshake.encode_handshake_msg(
    @handshake.CertificateVerify({ signature: Bytes::make(72, b'\xCC'), }),
  )
  let cv_sum = @handshake.inspect_handshake(cv_wire[:])
  assert_eq(cv_sum.msg_type, @handshake.HT_CERTIFICATE_VERIFY)
  assert_eq(cv_sum.msg_type_name, "CertificateVerify")
  assert_eq(cv_sum.total_wire_len, cv_wire.length())
  // 8a/8b/8c. ClientKeyExchange (ECC, raw ECDHE, 2B-prefixed ECDHE)
  let cke_ecc_wire = @handshake.encode_handshake_msg(
    @handshake.ClientKeyExchange(
      @handshake.ClientKeyExchange::Ecc(Bytes::make(145, b'\xDD')),
    ),
  )
  let cke_ecc_sum = @handshake.inspect_handshake(cke_ecc_wire[:])
  assert_eq(cke_ecc_sum.msg_type, @handshake.HT_CLIENT_KEY_EXCHANGE)
  assert_eq(cke_ecc_sum.msg_type_name, "ClientKeyExchange")
  assert_eq(cke_ecc_sum.total_wire_len, cke_ecc_wire.length())
  let cke_ecdhe_wire = @handshake.encode_handshake_msg(
    @handshake.ClientKeyExchange(
      @handshake.ClientKeyExchange::Ecdhe(ecdhe_params),
    ),
  )
  let cke_ecdhe_sum = @handshake.inspect_handshake(cke_ecdhe_wire[:])
  assert_eq(cke_ecdhe_sum.msg_type_name, "ClientKeyExchange")
  assert_eq(cke_ecdhe_sum.total_wire_len, cke_ecdhe_wire.length())
  let cke_prefixed = make_hs_frame(
    @handshake.HT_CLIENT_KEY_EXCHANGE,
    join_hs_bytes([b"\x00\x45", ecdhe_params]),
  )
  let cke_prefixed_sum = @handshake.inspect_handshake(cke_prefixed[:])
  assert_eq(cke_prefixed_sum.msg_type_name, "ClientKeyExchange")
  assert_eq(cke_prefixed_sum.total_wire_len, cke_prefixed.length())
  // 9. Finished (12B verify_data)
  let fin_wire = @handshake.encode_handshake_msg(
    @handshake.Finished({ verify_data: Bytes::make(12, b'\xEE'), }),
  )
  let fin_sum = @handshake.inspect_handshake(fin_wire[:])
  assert_eq(fin_sum.msg_type, @handshake.HT_FINISHED)
  assert_eq(fin_sum.msg_type_name, "Finished")
  assert_eq(fin_sum.body_len, 12)
  assert_eq(fin_sum.total_wire_len, 16)
  // Walking a coalesced multi-message flight using total_wire_len
  let coalesced = join_hs_bytes([sh_wire, cert_wire, ske_ecc_wire, shd_wire])
  let names : Array[String] = []
  let mut off = 0
  while off < coalesced.length() {
    let s = @handshake.inspect_handshake(coalesced[off:])
    names.push(s.msg_type_name)
    off = off + s.total_wire_len
  }
  assert_eq(off, coalesced.length())
  assert_eq(names, [
    "ServerHello", "Certificate", "ServerKeyExchange", "ServerHelloDone",
  ])
}

///|
test "inspect_handshake cleanly rejects truncated and malformed adversarial frames" {
  let ch_wire = @handshake.encode_handshake_msg(
    @handshake.ClientHello({
      version_major: b'\x01',
      version_minor: b'\x01',
      random: Bytes::make(32, b'\x01'),
      session_id: b"\xAA\xBB",
      cipher_suites: [0xE053U],
      compression_methods: b"\x00",
    }),
  )
  // Every strict prefix raises Incomplete
  for cut = 0; cut < ch_wire.length(); cut = cut + 1 {
    let is_inc = try {
      ignore(@handshake.inspect_handshake(ch_wire[:cut]))
      false
    } catch {
      @handshake.Incomplete => true
      _ => false
    }
    assert_true(is_inc)
  }
  // Oversized frame header (> 65536) raises InvalidLength immediately
  let over_err = try {
    ignore(@handshake.inspect_handshake(b"\x0B\x01\x00\x01"[:]))
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(over_err)
  // Unknown handshake message types raise InvalidMessageType
  for bad_mt in [b'\x00', b'\x05', b'\x99', b'\xFF'] {
    let bad_mt_err = try {
      ignore(@handshake.inspect_handshake(make_hs_frame(bad_mt, b"")[:]))
      false
    } catch {
      @handshake.InvalidMessageType(t) => t == bad_mt
      _ => false
    }
    assert_true(bad_mt_err)
  }
  // Collection of structurally malformed message bodies -> all must raise InvalidLength
  let malformed : Array[Bytes] = [
    // ClientHello: body too short
    make_hs_frame(@handshake.HT_CLIENT_HELLO, b"\x01\x01"),
    // ClientHello: odd cipher_suites byte length (3)
    make_hs_frame(
      @handshake.HT_CLIENT_HELLO,
      join_hs_bytes([
        b"\x01\x01",
        Bytes::make(32, b'\x00'),
        b"\x00\x00\x03\xE0\x53\x00\x01\x00",
      ]),
    ),
    // ClientHello: truncated extension TLV (ext_len=3, too short for 4B ext header)
    make_hs_frame(
      @handshake.HT_CLIENT_HELLO,
      join_hs_bytes([
        b"\x01\x01",
        Bytes::make(32, b'\x00'),
        b"\x00\x00\x02\xE0\x53\x01\x00\x00\x03\x00\x01\x02",
      ]),
    ),
    // ServerHello: truncated after session_id
    make_hs_frame(
      @handshake.HT_SERVER_HELLO,
      join_hs_bytes([b"\x01\x01", Bytes::make(32, b'\x00'), b"\x00\xE0"]),
    ),
    // Certificate: total_len mismatch
    make_hs_frame(@handshake.HT_CERTIFICATE, b"\x00\x00\x05\x01"),
    // Certificate: zero-length cert entry
    make_hs_frame(@handshake.HT_CERTIFICATE, b"\x00\x00\x03\x00\x00\x00"),
    // ServerKeyExchange: trailing byte after ECC signature
    make_hs_frame(@handshake.HT_SERVER_KEY_EXCHANGE, b"\x00\x02\xAA\xBB\xCC"),
    // ServerKeyExchange: truncated ECDHE params
    make_hs_frame(@handshake.HT_SERVER_KEY_EXCHANGE, b"\x03\x00\x29\x41\x04"),
    // CertificateRequest: zero cert_types_len
    make_hs_frame(@handshake.HT_CERTIFICATE_REQUEST, b"\x00\x00\x00"),
    // ServerHelloDone: non-empty body
    make_hs_frame(@handshake.HT_SERVER_HELLO_DONE, b"\x00"),
    // CertificateVerify: length mismatch
    make_hs_frame(@handshake.HT_CERTIFICATE_VERIFY, b"\x00\x04\x01\x02"),
    // ClientKeyExchange: empty / zero-length / truncated 4B ECDHE header
    make_hs_frame(@handshake.HT_CLIENT_KEY_EXCHANGE, b""),
    make_hs_frame(@handshake.HT_CLIENT_KEY_EXCHANGE, b"\x00\x00"),
    make_hs_frame(@handshake.HT_CLIENT_KEY_EXCHANGE, b"\x03\x00\x29\x41"),
    // Finished: wrong length (11B and 13B)
    make_hs_frame(@handshake.HT_FINISHED, Bytes::make(11, b'\x00')),
    make_hs_frame(@handshake.HT_FINISHED, Bytes::make(13, b'\x00')),
  ]
  for frame in malformed {
    let rejected = try {
      ignore(@handshake.inspect_handshake(frame[:]))
      false
    } catch {
      @handshake.InvalidLength => true
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "inspect_alert decodes all 18 GM/T 0024 alerts and rejects invalid payloads" {
  let alerts : Array[(Byte, String)] = [
    (b'\x00', "CloseNotify"),
    (b'\x0A', "UnexpectedMessage"),
    (b'\x14', "BadRecordMac"),
    (b'\x15', "DecryptionFailed"),
    (b'\x16', "RecordOverflow"),
    (b'\x28', "HandshakeFailure"),
    (b'\x2A', "BadCertificate"),
    (b'\x2B', "UnsupportedCertificate"),
    (b'\x2D', "CertificateExpired"),
    (b'\x2E', "CertificateUnknown"),
    (b'\x2F', "IllegalParameter"),
    (b'\x30', "UnknownCa"),
    (b'\x32', "DecodeError"),
    (b'\x33', "DecryptError"),
    (b'\x46', "ProtocolVersion"),
    (b'\x47', "InsufficientSecurity"),
    (b'\x50', "InternalError"),
    (b'\xC8', "UnsupportedSite2Site"),
  ]
  for entry in alerts {
    let (code, expected_name) = entry
    let (w_lvl, w_desc, w_name) = @handshake.inspect_alert(
      Bytes::from_array([b'\x01', code])[:],
    )
    assert_eq(w_lvl, b'\x01')
    assert_eq(w_desc, code)
    assert_eq(w_name, expected_name)
    let (f_lvl, f_desc, f_name) = @handshake.inspect_alert(
      Bytes::from_array([b'\x02', code])[:],
    )
    assert_eq(f_lvl, b'\x02')
    assert_eq(f_desc, code)
    assert_eq(f_name, expected_name)
  }
  // Truncated (< 2 bytes) -> Incomplete
  for short in [b"", b"\x02"] {
    let is_inc = try {
      ignore(@handshake.inspect_alert(short[:]))
      false
    } catch {
      @handshake.Incomplete => true
      _ => false
    }
    assert_true(is_inc)
  }
  // Oversized (> 2 bytes) -> InvalidLength
  let long_err = try {
    ignore(@handshake.inspect_alert(b"\x02\x14\x00"[:]))
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(long_err)
  // Invalid level / unknown description -> DecodeError
  let bad_lvl = try {
    ignore(@handshake.inspect_alert(b"\x03\x00"[:]))
    false
  } catch {
    @handshake.DecodeError(_) => true
    _ => false
  }
  assert_true(bad_lvl)
  let bad_desc = try {
    ignore(@handshake.inspect_alert(b"\x02\xFE"[:]))
    false
  } catch {
    @handshake.DecodeError(_) => true
    _ => false
  }
  assert_true(bad_desc)
}
