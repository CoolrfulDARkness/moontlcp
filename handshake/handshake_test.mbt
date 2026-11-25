///|
fn make_bytes(len : Int32, seed : Int32) -> Bytes {
  let out = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = ((i * 29 + seed * 13 + 5) & 0xFF).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn concat_all(parts : Array[Bytes]) -> Bytes {
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
test "Alert protocol exact RFC/GM/T 0024 wire codes and error handling" {
  assert_eq(@handshake.AlertLevel::Warning.to_byte(), b'\x01')
  assert_eq(@handshake.AlertLevel::Fatal.to_byte(), b'\x02')
  assert_eq(@handshake.AlertLevel::from_byte(b'\x01'), @handshake.Warning)
  assert_eq(@handshake.AlertLevel::from_byte(b'\x02'), @handshake.Fatal)
  let descriptions : Array[(@handshake.AlertDescription, Byte)] = [
    (@handshake.CloseNotify, b'\x00'),
    (@handshake.UnexpectedMessage, b'\x0A'),
    (@handshake.BadRecordMac, b'\x14'),
    (@handshake.DecryptionFailed, b'\x15'),
    (@handshake.RecordOverflow, b'\x16'),
    (@handshake.HandshakeFailure, b'\x28'),
    (@handshake.BadCertificate, b'\x2A'),
    (@handshake.UnsupportedCertificate, b'\x2B'),
    (@handshake.CertificateExpired, b'\x2D'),
    (@handshake.CertificateUnknown, b'\x2E'),
    (@handshake.IllegalParameter, b'\x2F'),
    (@handshake.UnknownCa, b'\x30'),
    (@handshake.AlertDescription::DecodeError, b'\x32'),
    (@handshake.DecryptError, b'\x33'),
    (@handshake.ProtocolVersion, b'\x46'),
    (@handshake.InsufficientSecurity, b'\x47'),
    (@handshake.InternalError, b'\x50'),
    (@handshake.UnsupportedSite2Site, b'\xC8'),
  ]
  for pair in descriptions {
    let (desc, code) = pair
    assert_eq(desc.to_byte(), code)
    assert_eq(@handshake.AlertDescription::from_byte(code), desc)
    let alert = @handshake.Alert::{
      level: @handshake.Fatal,
      description: desc,
    }
    let encoded = @handshake.encode_alert(alert)
    assert_eq(encoded.length(), 2)
    assert_eq(encoded[0], b'\x02')
    assert_eq(encoded[1], code)
    assert_eq(@handshake.decode_alert(encoded[:]), alert)
  }
  // Incomplete (< 2 bytes)
  let short_err = try {
    ignore(@handshake.decode_alert(b"\x01"[:]))
    false
  } catch {
    @handshake.Incomplete => true
    _ => false
  }
  assert_true(short_err)
  // Oversized (> 2 bytes)
  let long_err = try {
    ignore(@handshake.decode_alert(b"\x01\x00\x00"[:]))
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(long_err)
  // Invalid level & unknown description
  let bad_lvl = try {
    ignore(@handshake.decode_alert(b"\x03\x00"[:]))
    false
  } catch {
    @handshake.DecodeError(_) => true
    _ => false
  }
  assert_true(bad_lvl)
  let bad_desc = try {
    ignore(@handshake.decode_alert(b"\x02\xFE"[:]))
    false
  } catch {
    @handshake.DecodeError(_) => true
    _ => false
  }
  assert_true(bad_desc)
}

///|
test "4 GM/T 0024 cipher suites and SM2 ECDHE param helpers" {
  let suites : Array[(@handshake.CipherSuite, UInt32, Bool, Bool, String)] = [
    (@handshake.EcdheSm4CbcSm3, 0xE011U, false, true, "ECDHE_SM4_CBC_SM3"),
    (@handshake.EccSm4CbcSm3, 0xE013U, false, false, "ECC_SM4_CBC_SM3"),
    (@handshake.EcdheSm4GcmSm3, 0xE051U, true, true, "ECDHE_SM4_GCM_SM3"),
    (@handshake.EccSm4GcmSm3, 0xE053U, true, false, "ECC_SM4_GCM_SM3"),
  ]
  for entry in suites {
    let (s, code, gcm, ecdhe, name) = entry
    assert_eq(s.to_u16(), code)
    assert_eq(@handshake.CipherSuite::from_u16(code), Some(s))
    assert_eq(s.is_gcm(), gcm)
    assert_eq(s.is_ecdhe(), ecdhe)
    assert_eq(s.name(), name)
  }
  assert_eq(@handshake.CipherSuite::from_u16(0xC02FU), None)
  assert_eq(@handshake.CURVE_TYPE_NAMED, b'\x03')
  assert_eq(@handshake.NAMED_CURVE_SM2P256V1, 0x0029U)
  // Parse all 3 compatible SM2 curve IDs: 0x0029, 0x0020, 0x001D
  let pub_point = make_bytes(65, 1)
  for curve_id in [0x0029U, 0x0020U, 0x001DU] {
    let params = @handshake.build_ecdhe_params(curve_id, pub_point)
    assert_eq(params.length(), 4 + 65)
    assert_eq(params[0], b'\x03')
    assert_eq(params[3], b'\x41')
    let (parsed_curve, parsed_pub) = @handshake.parse_ecdhe_params(params[:])
    assert_eq(parsed_curve, curve_id)
    assert_eq(parsed_pub, pub_point)
  }
  // Reject non-SM2 curve ID (0x0017 = secp256r1)
  let bad_curve = @handshake.build_ecdhe_params(0x0017U, pub_point)
  let bad_curve_rej = try {
    ignore(@handshake.parse_ecdhe_params(bad_curve[:]))
    false
  } catch {
    @handshake.DecodeError(_) => true
    _ => false
  }
  assert_true(bad_curve_rej)
  // Verify TBS builders byte-for-byte
  let cr = make_bytes(32, 2)
  let sr = make_bytes(32, 3)
  let enc_cert = make_bytes(300, 4)
  let ecc_tbs = @handshake.build_ecc_ske_tbs(cr, sr, enc_cert)
  assert_eq(ecc_tbs.length(), 32 + 32 + 3 + 300)
  // 300 == 0x00012C
  assert_eq(ecc_tbs[64], b'\x00')
  assert_eq(ecc_tbs[65], b'\x01')
  assert_eq(ecc_tbs[66], b'\x2C')
  assert_eq(
    ecc_tbs,
    concat_all([
      cr,
      sr,
      Bytes::from_array([b'\x00', b'\x01', b'\x2C']),
      enc_cert,
    ]),
  )
  let ecdhe_params = @handshake.build_ecdhe_params(
    @handshake.NAMED_CURVE_SM2P256V1,
    pub_point,
  )
  let ecdhe_tbs = @handshake.build_ecdhe_ske_tbs(cr, sr, ecdhe_params)
  assert_eq(ecdhe_tbs, concat_all([cr, sr, ecdhe_params]))
}

///|
test "all 9 TLCP handshake messages wire-level round-trip (ECC and ECDHE)" {
  let cr = make_bytes(32, 10)
  let sr = make_bytes(32, 11)
  let sid = make_bytes(16, 12)
  // 1. ClientHello
  let ch = @handshake.ClientHello::{
    version_major: @record.TLCP_VERSION_MAJOR,
    version_minor: @record.TLCP_VERSION_MINOR,
    random: cr,
    session_id: sid,
    cipher_suites: [0xE051U, 0xE053U, 0xE011U, 0xE013U],
    compression_methods: b"\x00",
  }
  let ch_wire = @handshake.encode_handshake_msg(@handshake.ClientHello(ch))
  assert_eq(ch_wire[0], @handshake.HT_CLIENT_HELLO)
  let (t1, b1, n1) = @handshake.decode_handshake_frame(ch_wire[:])
  assert_eq(t1, @handshake.HT_CLIENT_HELLO)
  assert_eq(n1, ch_wire.length())
  assert_eq(
    @handshake.decode_handshake_msg(t1, b1, false),
    @handshake.ClientHello(ch),
  )
  // 2. ServerHello
  let sh = @handshake.ServerHello::{
    version_major: @record.TLCP_VERSION_MAJOR,
    version_minor: @record.TLCP_VERSION_MINOR,
    random: sr,
    session_id: sid,
    cipher_suite: @handshake.EccSm4GcmSm3,
    compression_method: b'\x00',
  }
  let sh_wire = @handshake.encode_handshake_msg(@handshake.ServerHello(sh))
  let (t2, b2, n2) = @handshake.decode_handshake_frame(sh_wire[:])
  assert_eq(t2, @handshake.HT_SERVER_HELLO)
  assert_eq(n2, sh_wire.length())
  assert_eq(
    @handshake.decode_handshake_msg(t2, b2, false),
    @handshake.ServerHello(sh),
  )
  // 3. Certificate (GM dual-cert: sign_cert + enc_cert + ca_cert)
  let cert_msg = @handshake.CertificateMsg::{
    certificates: [make_bytes(120, 20), make_bytes(135, 21), make_bytes(90, 22)],
  }
  let cert_wire = @handshake.encode_handshake_msg(
    @handshake.Certificate(cert_msg),
  )
  let (t3, b3, n3) = @handshake.decode_handshake_frame(cert_wire[:])
  assert_eq(t3, @handshake.HT_CERTIFICATE)
  assert_eq(n3, cert_wire.length())
  // Verify 3B total len = (3+120) + (3+135) + (3+90) = 354 = 0x000162
  assert_eq(b3[0], b'\x00')
  assert_eq(b3[1], b'\x01')
  assert_eq(b3[2], b'\x62')
  assert_eq(
    @handshake.decode_handshake_msg(t3, b3, false),
    @handshake.Certificate(cert_msg),
  )
  // 4a. ServerKeyExchange (ECC)
  let sig_der = make_bytes(71, 30)
  let ske_ecc = @handshake.ServerKeyExchange::Ecc(sig_der)
  let ske_ecc_wire = @handshake.encode_handshake_msg(
    @handshake.ServerKeyExchange(ske_ecc),
  )
  let (t4a, b4a, n4a) = @handshake.decode_handshake_frame(ske_ecc_wire[:])
  assert_eq(t4a, @handshake.HT_SERVER_KEY_EXCHANGE)
  assert_eq(n4a, ske_ecc_wire.length())
  assert_eq(b4a.length(), 2 + 71)
  assert_eq(
    @handshake.decode_handshake_msg(t4a, b4a, false),
    @handshake.ServerKeyExchange(ske_ecc),
  )
  // 4b. ServerKeyExchange (ECDHE)
  let ecdhe_params = @handshake.build_ecdhe_params(
    @handshake.NAMED_CURVE_SM2P256V1,
    make_bytes(65, 31),
  )
  let ske_ecdhe = @handshake.ServerKeyExchange::Ecdhe(ecdhe_params, sig_der)
  let ske_ecdhe_wire = @handshake.encode_handshake_msg(
    @handshake.ServerKeyExchange(ske_ecdhe),
  )
  let (t4b, b4b, n4b) = @handshake.decode_handshake_frame(ske_ecdhe_wire[:])
  assert_eq(t4b, @handshake.HT_SERVER_KEY_EXCHANGE)
  assert_eq(n4b, ske_ecdhe_wire.length())
  assert_eq(b4b.length(), ecdhe_params.length() + 2 + 71)
  assert_eq(
    @handshake.decode_handshake_msg(t4b, b4b, true),
    @handshake.ServerKeyExchange(ske_ecdhe),
  )
  // 5. CertificateRequest
  let cr_msg = @handshake.CertificateRequest::{
    cert_types: Bytes::from_array([b'\x40', b'\x01']),
    ca_names: [make_bytes(24, 40), make_bytes(30, 41)],
  }
  let cr_wire = @handshake.encode_handshake_msg(
    @handshake.CertificateRequest(cr_msg),
  )
  let (t5, b5, n5) = @handshake.decode_handshake_frame(cr_wire[:])
  assert_eq(t5, @handshake.HT_CERTIFICATE_REQUEST)
  assert_eq(n5, cr_wire.length())
  assert_eq(
    @handshake.decode_handshake_msg(t5, b5, false),
    @handshake.CertificateRequest(cr_msg),
  )
  // 6. ServerHelloDone
  let shd_wire = @handshake.encode_handshake_msg(@handshake.ServerHelloDone)
  assert_eq(shd_wire, Bytes::from_array([b'\x0E', b'\x00', b'\x00', b'\x00']))
  let (t6, b6, n6) = @handshake.decode_handshake_frame(shd_wire[:])
  assert_eq(t6, @handshake.HT_SERVER_HELLO_DONE)
  assert_eq(n6, 4)
  assert_eq(
    @handshake.decode_handshake_msg(t6, b6, false),
    @handshake.ServerHelloDone,
  )
  // 7. CertificateVerify
  let cv_msg = @handshake.CertificateVerify::{ signature: make_bytes(72, 50), }
  let cv_wire = @handshake.encode_handshake_msg(
    @handshake.CertificateVerify(cv_msg),
  )
  let (t7, b7, n7) = @handshake.decode_handshake_frame(cv_wire[:])
  assert_eq(t7, @handshake.HT_CERTIFICATE_VERIFY)
  assert_eq(n7, cv_wire.length())
  assert_eq(
    @handshake.decode_handshake_msg(t7, b7, false),
    @handshake.CertificateVerify(cv_msg),
  )
  // 8a. ClientKeyExchange (ECC)
  let cke_ecc = @handshake.ClientKeyExchange::Ecc(make_bytes(145, 60))
  let cke_ecc_wire = @handshake.encode_handshake_msg(
    @handshake.ClientKeyExchange(cke_ecc),
  )
  let (t8a, b8a, n8a) = @handshake.decode_handshake_frame(cke_ecc_wire[:])
  assert_eq(t8a, @handshake.HT_CLIENT_KEY_EXCHANGE)
  assert_eq(n8a, cke_ecc_wire.length())
  assert_eq(b8a.length(), 2 + 145)
  assert_eq(
    @handshake.decode_handshake_msg(t8a, b8a, false),
    @handshake.ClientKeyExchange(cke_ecc),
  )
  // 8b. ClientKeyExchange (ECDHE: raw params AND optional 2B length-prefixed params)
  let cke_ecdhe = @handshake.ClientKeyExchange::Ecdhe(ecdhe_params)
  let cke_ecdhe_wire = @handshake.encode_handshake_msg(
    @handshake.ClientKeyExchange(cke_ecdhe),
  )
  let (t8b, b8b, n8b) = @handshake.decode_handshake_frame(cke_ecdhe_wire[:])
  assert_eq(t8b, @handshake.HT_CLIENT_KEY_EXCHANGE)
  assert_eq(n8b, cke_ecdhe_wire.length())
  assert_eq(b8b.length(), ecdhe_params.length())
  assert_eq(
    @handshake.decode_handshake_msg(t8b, b8b, true),
    @handshake.ClientKeyExchange(cke_ecdhe),
  )
  // Optional 2B length prefix compatibility (length = 69 = 0x0045)
  let prefixed_body = concat_all([
    Bytes::from_array([b'\x00', b'\x45']),
    ecdhe_params,
  ])
  assert_eq(
    @handshake.decode_handshake_msg(
      @handshake.HT_CLIENT_KEY_EXCHANGE,
      prefixed_body[:],
      true,
    ),
    @handshake.ClientKeyExchange(cke_ecdhe),
  )
  // 9. Finished (12B)
  let fin_msg = @handshake.Finished::{ verify_data: make_bytes(12, 70), }
  let fin_wire = @handshake.encode_handshake_msg(@handshake.Finished(fin_msg))
  assert_eq(fin_wire.length(), 16)
  let (t9, b9, n9) = @handshake.decode_handshake_frame(fin_wire[:])
  assert_eq(t9, @handshake.HT_FINISHED)
  assert_eq(n9, 16)
  assert_eq(
    @handshake.decode_handshake_msg(t9, b9, false),
    @handshake.Finished(fin_msg),
  )
}

///|
test "decode_handshake_frame handles coalesced sticky packets and truncated half-packets" {
  let m1 = @handshake.encode_handshake_msg(
    @handshake.ServerHello({
      version_major: b'\x01',
      version_minor: b'\x01',
      random: make_bytes(32, 80),
      session_id: b"",
      cipher_suite: @handshake.EccSm4CbcSm3,
      compression_method: b'\x00',
    }),
  )
  let m2 = @handshake.encode_handshake_msg(
    @handshake.Certificate({ certificates: [make_bytes(40, 81)], }),
  )
  let m3 = @handshake.encode_handshake_msg(
    @handshake.ServerKeyExchange(
      @handshake.ServerKeyExchange::Ecc(make_bytes(64, 82)),
    ),
  )
  let m4 = @handshake.encode_handshake_msg(@handshake.ServerHelloDone)
  let stream = concat_all([m1, m2, m3, m4])
  let decoded_types : Array[Byte] = []
  let mut off = 0
  while off < stream.length() {
    let (mt, body, consumed) = @handshake.decode_handshake_frame(stream[off:])
    ignore(@handshake.decode_handshake_msg(mt, body, false))
    decoded_types.push(mt)
    off = off + consumed
  }
  assert_eq(off, stream.length())
  assert_eq(decoded_types, [
    @handshake.HT_SERVER_HELLO,
    @handshake.HT_CERTIFICATE,
    @handshake.HT_SERVER_KEY_EXCHANGE,
    @handshake.HT_SERVER_HELLO_DONE,
  ])
  // Every strict prefix of m2 must raise Incomplete
  for cut = 0; cut < m2.length(); cut = cut + 1 {
    let inc = try {
      ignore(@handshake.decode_handshake_frame(m2[:cut]))
      false
    } catch {
      @handshake.Incomplete => true
      _ => false
    }
    assert_true(inc)
  }
}

///|
test "Key Schedule (CBC 128B vs GCM 40B), verify_data, Transcript, and RecordLayer integration" {
  let pms = make_bytes(48, 90)
  let cr = make_bytes(32, 91)
  let sr = make_bytes(32, 92)
  // 1. Master secret (48B)
  let ms = @handshake.derive_master_secret(pms, cr, sr)
  assert_eq(ms.length(), 48)
  assert_eq(ms, @sm3.tlcp_prf(pms, b"master secret", concat_all([cr, sr]), 48))
  // 2. CBC KeyBlock (32/32/16/16/16/16 = 128B)
  let kb_cbc = @handshake.derive_key_block(ms, sr, cr, @handshake.EccSm4CbcSm3)
  assert_eq(kb_cbc.client_mac_key.length(), 32)
  assert_eq(kb_cbc.server_mac_key.length(), 32)
  assert_eq(kb_cbc.client_write_key.length(), 16)
  assert_eq(kb_cbc.server_write_key.length(), 16)
  assert_eq(kb_cbc.client_write_iv.length(), 16)
  assert_eq(kb_cbc.server_write_iv.length(), 16)
  let expected_cbc = @sm3.tlcp_prf(
    ms,
    b"key expansion",
    concat_all([sr, cr]),
    128,
  )
  assert_eq(
    concat_all([
      kb_cbc.client_mac_key,
      kb_cbc.server_mac_key,
      kb_cbc.client_write_key,
      kb_cbc.server_write_key,
      kb_cbc.client_write_iv,
      kb_cbc.server_write_iv,
    ]),
    expected_cbc,
  )
  // Verify CBC KeyBlock works end-to-end with RecordLayer
  let c_tx = @record.RecordLayer::new()
  let s_rx = @record.RecordLayer::new()
  c_tx.set_cipher(
    @record.CipherState::new_cbc(kb_cbc.client_write_key, kb_cbc.client_mac_key),
  )
  s_rx.set_cipher(
    @record.CipherState::new_cbc(kb_cbc.client_write_key, kb_cbc.client_mac_key),
  )
  let cbc_wire = c_tx.seal(
    @record.ApplicationData,
    b"CBC keyblock ok",
    kb_cbc.client_write_iv,
  )
  let (cbc_raw, _) = @record.decode_record(cbc_wire[:])
  assert_eq(s_rx.open(cbc_raw), b"CBC keyblock ok")
  // 3. GCM KeyBlock (0/0/16/16/4/4 = 40B)
  let kb_gcm = @handshake.derive_key_block(
    ms,
    sr,
    cr,
    @handshake.EcdheSm4GcmSm3,
  )
  assert_eq(kb_gcm.client_mac_key.length(), 0)
  assert_eq(kb_gcm.server_mac_key.length(), 0)
  assert_eq(kb_gcm.client_write_key.length(), 16)
  assert_eq(kb_gcm.server_write_key.length(), 16)
  assert_eq(kb_gcm.client_write_iv.length(), 4)
  assert_eq(kb_gcm.server_write_iv.length(), 4)
  let expected_gcm = @sm3.tlcp_prf(
    ms,
    b"key expansion",
    concat_all([sr, cr]),
    40,
  )
  assert_eq(
    concat_all([
      kb_gcm.client_write_key,
      kb_gcm.server_write_key,
      kb_gcm.client_write_iv,
      kb_gcm.server_write_iv,
    ]),
    expected_gcm,
  )
  // Verify GCM KeyBlock works end-to-end with RecordLayer
  let gc_tx = @record.RecordLayer::new()
  let gs_rx = @record.RecordLayer::new()
  gc_tx.set_cipher(
    @record.CipherState::new_gcm(
      kb_gcm.client_write_key,
      kb_gcm.client_write_iv,
    ),
  )
  gs_rx.set_cipher(
    @record.CipherState::new_gcm(
      kb_gcm.client_write_key,
      kb_gcm.client_write_iv,
    ),
  )
  let gcm_wire = gc_tx.seal(
    @record.ApplicationData,
    b"GCM keyblock ok",
    make_bytes(8, 93),
  )
  let (gcm_raw, _) = @record.decode_record(gcm_wire[:])
  assert_eq(gs_rx.open(gcm_raw), b"GCM keyblock ok")
  // 4. Transcript rolling SM3 hash and Finished verify_data
  let tr = @handshake.Transcript::new()
  assert_eq(tr.raw_bytes(), b"")
  assert_eq(tr.hash(), @sm3.sm3(b""))
  let msg_a = @handshake.encode_handshake_msg(@handshake.ServerHelloDone)
  let msg_b = @handshake.encode_handshake_msg(
    @handshake.Finished({ verify_data: make_bytes(12, 94), }),
  )
  tr.update(msg_a)
  let h1 = tr.hash()
  assert_eq(h1, @sm3.sm3(msg_a))
  // Calling hash() must not mutate the rolling state
  assert_eq(tr.hash(), h1)
  tr.update(msg_b)
  assert_eq(tr.raw_bytes(), concat_all([msg_a, msg_b]))
  assert_eq(tr.hash(), @sm3.sm3(concat_all([msg_a, msg_b])))
  let vd_c = @handshake.compute_verify_data(ms, true, tr.hash())
  let vd_s = @handshake.compute_verify_data(ms, false, tr.hash())
  assert_eq(vd_c.length(), 12)
  assert_eq(vd_s.length(), 12)
  assert_eq(vd_c, @sm3.tlcp_prf(ms, b"client finished", tr.hash(), 12))
  assert_eq(vd_s, @sm3.tlcp_prf(ms, b"server finished", tr.hash(), 12))
  assert_true(vd_c != vd_s)
}

///|
test "handshake decoder rejects malformed lengths, invalid versions, unsupported suites, and bad Finished" {
  // 1. Unknown message type
  let bad_mt = try {
    ignore(@handshake.decode_handshake_msg(b'\x99', b""[:], false))
    false
  } catch {
    @handshake.InvalidMessageType(b'\x99') => true
    _ => false
  }
  assert_true(bad_mt)
  // 2. ClientHello wrong version (0x0303)
  let bad_ch_wire = @handshake.encode_handshake_msg(
    @handshake.ClientHello({
      version_major: b'\x03',
      version_minor: b'\x03',
      random: make_bytes(32, 1),
      session_id: b"",
      cipher_suites: [0xE013U],
      compression_methods: b"\x00",
    }),
  )
  let (_, bad_ch_body, _) = @handshake.decode_handshake_frame(bad_ch_wire[:])
  let bad_ch_ver = try {
    ignore(
      @handshake.decode_handshake_msg(
        @handshake.HT_CLIENT_HELLO,
        bad_ch_body,
        false,
      ),
    )
    false
  } catch {
    @handshake.InvalidVersion(b'\x03', b'\x03') => true
    _ => false
  }
  assert_true(bad_ch_ver)
  // 3. ServerHello unsupported cipher suite (0xC02F)
  let bad_sh_body = concat_all([
    Bytes::from_array([b'\x01', b'\x01']),
    make_bytes(32, 2),
    Bytes::from_array([b'\x00', b'\xC0', b'\x2F', b'\x00']),
  ])
  let bad_suite = try {
    ignore(
      @handshake.decode_handshake_msg(
        @handshake.HT_SERVER_HELLO,
        bad_sh_body[:],
        false,
      ),
    )
    false
  } catch {
    @handshake.UnsupportedCipherSuite => true
    _ => false
  }
  assert_true(bad_suite)
  // 4. Finished wrong lengths (0, 11, 13 bytes)
  for bad_len in [0, 11, 13] {
    let bad_fin = try {
      ignore(
        @handshake.decode_handshake_msg(
          @handshake.HT_FINISHED,
          make_bytes(bad_len, 3)[:],
          false,
        ),
      )
      false
    } catch {
      @handshake.InvalidLength => true
      _ => false
    }
    assert_true(bad_fin)
  }
  // 5. ServerHelloDone non-empty body
  let bad_shd = try {
    ignore(
      @handshake.decode_handshake_msg(
        @handshake.HT_SERVER_HELLO_DONE,
        b"\x00"[:],
        false,
      ),
    )
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(bad_shd)
  // 6. Malformed Certificate (total_len mismatch / zero-length cert)
  let bad_cert1 = try {
    ignore(
      @handshake.decode_handshake_msg(
        @handshake.HT_CERTIFICATE,
        Bytes::from_array([b'\x00', b'\x00', b'\x05', b'\x01'])[:],
        false,
      ),
    )
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(bad_cert1)
  let bad_cert2 = try {
    ignore(
      @handshake.decode_handshake_msg(
        @handshake.HT_CERTIFICATE,
        Bytes::from_array([b'\x00', b'\x00', b'\x03', b'\x00', b'\x00', b'\x00'])[:],
        false,
      ),
    )
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(bad_cert2)
  // 7. Malformed ServerKeyExchange / ClientKeyExchange / CertificateVerify (zero length / trailing bytes)
  let bad_ske = try {
    ignore(
      @handshake.decode_handshake_msg(
        @handshake.HT_SERVER_KEY_EXCHANGE,
        Bytes::from_array([b'\x00', b'\x02', b'\xAA', b'\xBB', b'\xCC'])[:],
        false,
      ),
    )
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(bad_ske)
  let bad_cke_ecc = try {
    ignore(
      @handshake.decode_handshake_msg(
        @handshake.HT_CLIENT_KEY_EXCHANGE,
        Bytes::from_array([b'\x00', b'\x00'])[:],
        false,
      ),
    )
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(bad_cke_ecc)
  let bad_cke_ecdhe = try {
    ignore(
      @handshake.decode_handshake_msg(
        @handshake.HT_CLIENT_KEY_EXCHANGE,
        b""[:],
        true,
      ),
    )
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(bad_cke_ecdhe)
  let bad_cv = try {
    ignore(
      @handshake.decode_handshake_msg(
        @handshake.HT_CERTIFICATE_VERIFY,
        Bytes::from_array([b'\x00', b'\x05', b'\x01'])[:],
        false,
      ),
    )
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(bad_cv)
}
