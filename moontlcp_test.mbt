///|
/// Blackbox integration tests for the root `CoolrfulDARkness/moontlcp` facade API.

///|
test "root facade cryptography entry points (SM3, HMAC-SM3, PRF, SM4-GCM, SM2)" {
  // SM3 & HMAC-SM3 & TLCP PRF
  let digest = @moontlcp.sm3_hash(b"abc")
  assert_eq(digest.length(), 32)
  assert_eq(digest[0], b'\x66')
  assert_eq(digest[1], b'\xc7')
  let mac = @moontlcp.hmac_sm3(b"secret-key", b"message")
  assert_eq(mac.length(), 32)
  let prf_out = @moontlcp.tlcp_prf(b"secret", b"master secret", b"seed", 48)
  assert_eq(prf_out.length(), 48)
  // SM4-GCM round-trip
  let key = Bytes::make(16, b'\x11')
  let iv = Bytes::make(12, b'\x22')
  let aad = b"tlcp-aad"
  let msg = b"Hello MoonTLCP root facade!"
  let (ct, tag) = @moontlcp.sm4_gcm_encrypt(key, iv, aad, msg)
  assert_eq(tag.length(), 16)
  assert_eq(@moontlcp.sm4_gcm_decrypt(key, iv, aad, ct, tag), msg)
  // SM2 Sign/Verify & Encrypt/Decrypt via test PKI keys
  let pki = @moontlcp.generate_test_pki(b"root-facade-crypto")
  let id = b"1234567812345678"
  let sig = @moontlcp.sm2_sign_der(pki.server_sign_priv, id, msg)
  assert_true(
    @moontlcp.sm2_verify_der(pki.server_sign_cert.public_key, id, msg, sig),
  )
  assert_true(
    !@moontlcp.sm2_verify_der(
      pki.server_sign_cert.public_key,
      id,
      b"tampered",
      sig,
    ),
  )
  let sm2_ct = @moontlcp.sm2_encrypt_asn1(
    pki.server_enc_cert.public_key,
    msg,
    b"enc-seed",
  )
  assert_eq(@moontlcp.sm2_decrypt_asn1(pki.server_enc_priv, sm2_ct), msg)
}

///|
test "root facade X.509 DER/PEM parsing and dual-certificate verification" {
  let pki = @moontlcp.generate_test_pki(b"root-facade-x509")
  let parsed_ca = @moontlcp.parse_cert_der(pki.ca_cert.raw_der)
  assert_eq(parsed_ca.subject_cn, pki.ca_cert.subject_cn)
  let pem_bundle = pki.server_sign_cert.to_pem() +
    "\n" +
    pki.server_enc_cert.to_pem()
  let parsed_pem = @moontlcp.parse_certs_pem(pem_bundle)
  assert_eq(parsed_pem.length(), 2)
  let verified = @moontlcp.verify_dual_certs(
    [parsed_pem[0].raw_der, parsed_pem[1].raw_der],
    [parsed_ca],
  )
  assert_eq(verified.sign_cert.raw_der, pki.server_sign_cert.raw_der)
  assert_eq(verified.enc_cert.raw_der, pki.server_enc_cert.raw_der)
}

///|
test "root facade TLCP handshake loop, bidirectional app data, and session resumption" {
  let pki = @moontlcp.generate_test_pki(b"root-facade-tlcp")
  let suites = @moontlcp.default_cipher_suites()
  assert_eq(suites.length(), 4)
  let store = @moontlcp.new_session_store()
  // 1. Full handshake
  let client1 = @moontlcp.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: suites,
    client_certs: None,
    resume_session: None,
    seed: b"facade-c1",
  })
  let server1 = @moontlcp.new_server({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: suites,
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(store),
    seed: b"facade-s1",
  })
  let (c1_bytes, s1_bytes) = @moontlcp.run_handshake_loop(client1, server1)
  assert_true(c1_bytes > 0 && s1_bytes > 0)
  assert_true(client1.is_established() && server1.is_established())
  let wire = client1.write_app_data(b"hello via facade")
  let evs = server1.feed(wire[:])
  assert_eq(evs.length(), 1)
  // 2. Abbreviated session resumption handshake uses fewer bytes than full handshake
  let saved = client1.export_session()
  assert_true(saved is Some(_))
  let client2 = @moontlcp.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: suites,
    client_certs: None,
    resume_session: saved,
    seed: b"facade-c2",
  })
  let server2 = @moontlcp.new_server({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: suites,
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(store),
    seed: b"facade-s2",
  })
  let (c2_bytes, s2_bytes) = @moontlcp.run_handshake_loop(client2, server2)
  assert_true(client2.is_resumed() && server2.is_resumed())
  assert_true(c2_bytes + s2_bytes < c1_bytes + s1_bytes)
}

///|
test "root facade stateless wire inspection on live TLCP 1.1 ECC and mTLCP ECDHE flights" {
  let pki = @moontlcp.generate_test_pki(b"root-facade-wire-inspect")
  // 1. Live ECC_SM4_GCM_SM3 handshake flight-by-flight wire dissection
  let client = @moontlcp.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"inspect-ecc-c",
  })
  let server = @moontlcp.new_server({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed: b"inspect-ecc-s",
  })
  // Flight 1: ClientHello
  let flight1 = client.start_handshake()
  let f1_recs : Array[@moontlcp.RecordView] = @moontlcp.inspect_record_stream(
    flight1[:],
  )
  assert_eq(f1_recs.length(), 1)
  assert_eq(f1_recs[0].content_type, b'\x16')
  assert_eq(f1_recs[0].content_type_name, "Handshake")
  assert_eq(f1_recs[0].is_tlcp_1_1, true)
  let f1_single = @moontlcp.inspect_record(flight1[:])
  assert_eq(f1_single, f1_recs[0])
  let ch_payload = flight1[f1_recs[0].payload_offset:f1_recs[0].payload_offset +
    f1_recs[0].payload_len]
  let ch_sum : @moontlcp.HandshakeSummary = @moontlcp.inspect_handshake(
    ch_payload,
  )
  assert_eq(ch_sum.msg_type_name, "ClientHello")
  assert_eq(ch_sum.protocol_version, 0x0101U)
  assert_eq(ch_sum.cipher_suites, [0xE053U])
  assert_eq(ch_sum.selected_suite, None)
  // Flight 2: ServerHello + Certificate(Sign+Enc) + ServerKeyExchange + ServerHelloDone
  ignore(server.feed(flight1[:]))
  let flight2 = server.take_outbound()
  let f2_recs = @moontlcp.inspect_record_stream(flight2[:])
  assert_true(f2_recs.length() >= 4)
  let f2_hs_names : Array[String] = []
  let mut saw_server_dual_certs = false
  let mut saw_selected_suite : UInt32? = None
  for r in f2_recs {
    assert_eq(r.content_type_name, "Handshake")
    assert_eq(r.is_tlcp_1_1, true)
    let payload = flight2[r.payload_offset:r.payload_offset + r.payload_len]
    let mut off = 0
    while off < payload.length() {
      let hs = @moontlcp.inspect_handshake(payload[off:])
      f2_hs_names.push(hs.msg_type_name)
      if hs.msg_type == @handshake.HT_SERVER_HELLO {
        saw_selected_suite = hs.selected_suite
      }
      if hs.msg_type == @handshake.HT_CERTIFICATE {
        assert_eq(hs.cert_count, 2)
        saw_server_dual_certs = true
      }
      off = off + hs.total_wire_len
    }
  }
  assert_eq(f2_hs_names, [
    "ServerHello", "Certificate", "ServerKeyExchange", "ServerHelloDone",
  ])
  assert_eq(saw_selected_suite, Some(0xE053U))
  assert_true(saw_server_dual_certs)
  // Flight 3: ClientKeyExchange + ChangeCipherSpec + Encrypted Finished
  ignore(client.feed(flight2[:]))
  let flight3 = client.take_outbound()
  let f3_recs = @moontlcp.inspect_record_stream(flight3[:])
  assert_eq(f3_recs.length(), 3)
  assert_eq(f3_recs[0].content_type_name, "Handshake")
  assert_eq(f3_recs[1].content_type_name, "ChangeCipherSpec")
  assert_eq(f3_recs[2].content_type_name, "Handshake")
  let cke_payload = flight3[f3_recs[0].payload_offset:f3_recs[0].payload_offset +
    f3_recs[0].payload_len]
  assert_eq(
    @moontlcp.inspect_handshake(cke_payload).msg_type_name,
    "ClientKeyExchange",
  )
  // 2. Live mTLCP ECDHE_SM4_CBC_SM3 flight inspection (CertificateRequest + Client Certificate + CertificateVerify)
  let m_client = @moontlcp.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EcdheSm4CbcSm3],
    client_certs: Some(
      (
        pki.client_sign_cert,
        pki.client_sign_priv,
        pki.client_enc_cert,
        pki.client_enc_priv,
      ),
    ),
    resume_session: None,
    seed: b"inspect-mtcp-c",
  })
  let m_server = @moontlcp.new_server({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EcdheSm4CbcSm3],
    require_client_cert: true,
    client_trust_anchors: [pki.ca_cert],
    session_store: None,
    seed: b"inspect-mtcp-s",
  })
  let mf1 = m_client.start_handshake()
  ignore(m_server.feed(mf1[:]))
  let mf2 = m_server.take_outbound()
  let mf2_names : Array[String] = []
  for r in @moontlcp.inspect_record_stream(mf2[:]) {
    let payload = mf2[r.payload_offset:r.payload_offset + r.payload_len]
    let mut off = 0
    while off < payload.length() {
      let hs = @moontlcp.inspect_handshake(payload[off:])
      mf2_names.push(hs.msg_type_name)
      off = off + hs.total_wire_len
    }
  }
  assert_eq(mf2_names, [
    "ServerHello", "Certificate", "ServerKeyExchange", "CertificateRequest", "ServerHelloDone",
  ])
  ignore(m_client.feed(mf2[:]))
  let mf3 = m_client.take_outbound()
  let mf3_recs = @moontlcp.inspect_record_stream(mf3[:])
  let mf3_plain_hs : Array[String] = []
  for r in mf3_recs {
    if r.content_type_name == "ChangeCipherSpec" {
      break
    }
    let payload = mf3[r.payload_offset:r.payload_offset + r.payload_len]
    let mut off = 0
    while off < payload.length() {
      let hs = @moontlcp.inspect_handshake(payload[off:])
      if hs.msg_type == @handshake.HT_CERTIFICATE {
        assert_eq(hs.cert_count, 2)
      }
      mf3_plain_hs.push(hs.msg_type_name)
      off = off + hs.total_wire_len
    }
  }
  assert_eq(mf3_plain_hs, [
    "Certificate", "ClientKeyExchange", "CertificateVerify",
  ])
  // 3. Live Fatal Alert wire inspection from TLS 1.2 (0x0303) downgrade attempt
  let downgrade_probe = Bytes::from_array([
    b'\x16', b'\x03', b'\x03', b'\x00', b'\x04', b'\x0E', b'\x00', b'\x00', b'\x00',
  ])
  let probe_view = @moontlcp.inspect_record(downgrade_probe[:])
  assert_eq(probe_view.is_tlcp_1_1, false)
  assert_eq(probe_view.version_major, b'\x03')
  assert_eq(probe_view.version_minor, b'\x03')
  let guard_server = @moontlcp.new_server({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: @moontlcp.default_cipher_suites(),
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed: b"inspect-alert-s",
  })
  let downgrade_rejected = try {
    ignore(guard_server.feed(downgrade_probe[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.ProtocolVersion, _) => true
    _ => false
  }
  assert_true(downgrade_rejected)
  let alert_wire = guard_server.take_outbound()
  let alert_rec = @moontlcp.inspect_record(alert_wire[:])
  assert_eq(alert_rec.content_type_name, "Alert")
  assert_eq(alert_rec.is_tlcp_1_1, true)
  assert_eq(alert_rec.payload_len, 2)
  let (lvl, desc, name) = @moontlcp.inspect_alert(
    alert_wire[alert_rec.payload_offset:alert_rec.payload_offset +
    alert_rec.payload_len],
  )
  assert_eq(lvl, b'\x02')
  assert_eq(desc, b'\x46')
  assert_eq(name, "ProtocolVersion")
  // 4. Adversarial malformed/truncated frames via root facade
  let bad_rec = try {
    ignore(@moontlcp.inspect_record(b"\x16\x01\x01\x00"[:]))
    false
  } catch {
    @record.Incomplete => true
    _ => false
  }
  assert_true(bad_rec)
  let bad_hs = try {
    ignore(@moontlcp.inspect_handshake(b"\x01\x00\x00\x02\x01\x01"[:]))
    false
  } catch {
    @handshake.InvalidLength => true
    _ => false
  }
  assert_true(bad_hs)
  let bad_alert = try {
    ignore(@moontlcp.inspect_alert(b"\x02"[:]))
    false
  } catch {
    @handshake.Incomplete => true
    _ => false
  }
  assert_true(bad_alert)
}
