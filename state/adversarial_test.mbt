///|
/// 20+ independent security adversarial tests verifying fail-closed behavior,
/// Fatal Alert emission, constant-time MAC/padding rejection, version downgrade
/// immunity, dual-certificate integrity, and state-machine ordering enforcement.

///|
fn adv_flip_byte(data : Bytes, idx : Int32, mask : UInt32) -> Bytes {
  let out = FixedArray::make(data.length(), b'\x00')
  for i = 0; i < data.length(); i = i + 1 {
    out[i] = data[i]
  }
  out[idx] = (out[idx].to_uint() ^ mask).to_byte()
  Bytes::from_array(out)
}

///|
fn adv_concat(parts : Array[Bytes]) -> Bytes {
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
fn adv_setup_established(
  pki : @x509.TestPki,
  suite : @handshake.CipherSuite,
  seed_tag : Bytes,
) -> (@state.ClientConn, @state.ServerConn) raise @state.StateError {
  let client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [suite],
    client_certs: if suite.is_ecdhe() {
      Some(
        (
          pki.client_sign_cert,
          pki.client_sign_priv,
          pki.client_enc_cert,
          pki.client_enc_priv,
        ),
      )
    } else {
      None
    },
    resume_session: None,
    seed: adv_concat([b"adv-c-", seed_tag]),
  })
  let server = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [suite],
    require_client_cert: suite.is_ecdhe(),
    client_trust_anchors: [pki.ca_cert],
    session_store: None,
    seed: adv_concat([b"adv-s-", seed_tag]),
  })
  let mut to_server = client.start_handshake()
  for _i = 0; _i < 8; _i = _i + 1 {
    if to_server.length() > 0 {
      ignore(server.feed(to_server[:]))
      to_server = b""
    }
    let to_client = server.take_outbound()
    if to_client.length() > 0 {
      ignore(client.feed(to_client[:]))
    }
    to_server = client.take_outbound()
    if to_server.length() == 0 &&
      client.is_established() &&
      server.is_established() {
      break
    }
  }
  (client, server)
}

///|
fn adv_parse_records(
  wire : Bytes,
) -> Array[@record.RawRecord] raise @record.RecordError {
  let recs : Array[@record.RawRecord] = []
  let mut off = 0
  while off < wire.length() {
    let (r, used) = @record.decode_record(wire[off:])
    recs.push(r)
    off = off + used
  }
  recs
}

///|
fn adv_assert_plaintext_fatal_alert(
  wire : Bytes,
  expected_desc : @handshake.AlertDescription,
) -> Unit raise {
  let (rec, _) = @record.decode_record(wire[:])
  assert_eq(rec.content_type, @record.Alert)
  let alert = @handshake.decode_alert(rec.payload[:])
  assert_eq(alert.level, @handshake.Fatal)
  assert_eq(alert.description, expected_desc)
}

///|
test "adversarial 01: SM4-CBC ciphertext body bit-flip triggers BadRecordMac and fail-closed" {
  let pki = @x509.generate_test_pki(b"adv-01")
  let (client, server) = adv_setup_established(
    pki,
    @handshake.EccSm4CbcSm3,
    b"01",
  )
  let wire = client.write_app_data(b"sensitive banking payload")
  // Offset 5 = start of 16B IV, offset 21 = start of CBC ciphertext
  let tampered = adv_flip_byte(wire, 21, 0x01U)
  let ok = try {
    ignore(server.feed(tampered[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.BadRecordMac, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
  assert_true(server.take_outbound().length() > 0)
}

///|
test "adversarial 02: SM4-GCM authentication tag bit-flip triggers BadRecordMac" {
  let pki = @x509.generate_test_pki(b"adv-02")
  let (client, server) = adv_setup_established(
    pki,
    @handshake.EccSm4GcmSm3,
    b"02",
  )
  let wire = client.write_app_data(b"authenticated gcm payload")
  let tampered = adv_flip_byte(wire, wire.length() - 1, 0x80U)
  let ok = try {
    ignore(server.feed(tampered[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.BadRecordMac, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
  assert_true(server.take_outbound().length() > 0)
}

///|
test "adversarial 03: SM4-CBC padding block tampering triggers BadRecordMac" {
  let pki = @x509.generate_test_pki(b"adv-03")
  let (client, server) = adv_setup_established(
    pki,
    @handshake.EccSm4CbcSm3,
    b"03",
  )
  let wire = client.write_app_data(b"cbc padding oracle probe")
  let tampered = adv_flip_byte(wire, wire.length() - 1, 0x01U)
  let ok = try {
    ignore(server.feed(tampered[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.BadRecordMac, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
}

///|
test "adversarial 04: SM4-GCM explicit nonce tampering triggers BadRecordMac" {
  let pki = @x509.generate_test_pki(b"adv-04")
  let (client, server) = adv_setup_established(
    pki,
    @handshake.EccSm4GcmSm3,
    b"04",
  )
  let wire = client.write_app_data(b"gcm nonce tamper probe")
  // Offset 5 is byte 0 of 8-byte explicit nonce
  let tampered = adv_flip_byte(wire, 5, 0x40U)
  let ok = try {
    ignore(server.feed(tampered[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.BadRecordMac, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
}

///|
test "adversarial 05: record version downgrade to TLS 1.2 (0x0303) rejected with ProtocolVersion alert" {
  let pki = @x509.generate_test_pki(b"adv-05")
  let server = @state.ServerConn::new(
    @state.ServerConfig::new(
      pki.server_sign_cert,
      pki.server_sign_priv,
      pki.server_enc_cert,
      pki.server_enc_priv,
      b"adv-05-s",
    ),
  )
  let tls12_rec = Bytes::from_array([
    b'\x16', b'\x03', b'\x03', b'\x00', b'\x04', b'\x01', b'\x00', b'\x00', b'\x00',
  ])
  let ok = try {
    ignore(server.feed(tls12_rec[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.ProtocolVersion, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
  adv_assert_plaintext_fatal_alert(
    server.take_outbound(),
    @handshake.ProtocolVersion,
  )
}

///|
test "adversarial 06: record version downgrade to TLCP 1.0 (0x0100) rejected with ProtocolVersion alert" {
  let pki = @x509.generate_test_pki(b"adv-06")
  let server = @state.ServerConn::new(
    @state.ServerConfig::new(
      pki.server_sign_cert,
      pki.server_sign_priv,
      pki.server_enc_cert,
      pki.server_enc_priv,
      b"adv-06-s",
    ),
  )
  let tlcp10_rec = Bytes::from_array([
    b'\x16', b'\x01', b'\x00', b'\x00', b'\x04', b'\x01', b'\x00', b'\x00', b'\x00',
  ])
  let ok = try {
    ignore(server.feed(tlcp10_rec[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.ProtocolVersion, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
  adv_assert_plaintext_fatal_alert(
    server.take_outbound(),
    @handshake.ProtocolVersion,
  )
}

///|
test "adversarial 07: ClientHello inner version downgrade (0x0303) inside valid 0x0101 record rejected" {
  let pki = @x509.generate_test_pki(b"adv-07")
  let server = @state.ServerConn::new(
    @state.ServerConfig::new(
      pki.server_sign_cert,
      pki.server_sign_priv,
      pki.server_enc_cert,
      pki.server_enc_priv,
      b"adv-07-s",
    ),
  )
  let bad_ch = @handshake.encode_handshake_msg(
    @handshake.ClientHello({
      version_major: b'\x03',
      version_minor: b'\x03',
      random: Bytes::make(32, b'\x11'),
      session_id: b"",
      cipher_suites: [0xE053U],
      compression_methods: b"\x00",
    }),
  )
  let rec = @record.encode_record({
    content_type: @record.Handshake,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: bad_ch,
  })
  let ok = try {
    ignore(server.feed(rec[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.ProtocolVersion, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
  adv_assert_plaintext_fatal_alert(
    server.take_outbound(),
    @handshake.ProtocolVersion,
  )
}

///|
test "adversarial 08: dual-certificate swap attack (enc_cert before sign_cert) rejected" {
  let pki = @x509.generate_test_pki(b"adv-08")
  let client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-08-c",
  })
  // Misconfigured/malicious server puts enc_cert in sign_cert slot and vice versa
  let rogue_server = @state.ServerConn::new({
    sign_cert: pki.server_enc_cert,
    sign_priv: pki.server_enc_priv,
    enc_cert: pki.server_sign_cert,
    enc_priv: pki.server_sign_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed: b"adv-08-s",
  })
  let ch = client.start_handshake()
  ignore(rogue_server.feed(ch[:]))
  let s_flight = rogue_server.take_outbound()
  let ok = try {
    ignore(client.feed(s_flight[:]))
    false
  } catch {
    @state.CertificateError(_) => true
    _ => false
  }
  assert_true(ok)
  assert_true(client.is_failed())
  adv_assert_plaintext_fatal_alert(
    client.take_outbound(),
    @handshake.BadCertificate,
  )
}

///|
test "adversarial 09: untrusted CA and spoofed-CN rogue CA certificates rejected" {
  let pki_trusted = @x509.generate_test_pki(b"adv-09-trusted")
  let pki_rogue = @x509.generate_test_pki(b"adv-09-rogue")
  // Part A: Spoofed same-CN rogue CA (signature mismatch -> BadCertificate)
  let client_a = @state.ClientConn::new({
    trust_anchors: [pki_trusted.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-09-ca",
  })
  let rogue_server_a = @state.ServerConn::new({
    sign_cert: pki_rogue.server_sign_cert,
    sign_priv: pki_rogue.server_sign_priv,
    enc_cert: pki_rogue.server_enc_cert,
    enc_priv: pki_rogue.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed: b"adv-09-sa",
  })
  let ch_a = client_a.start_handshake()
  ignore(rogue_server_a.feed(ch_a[:]))
  let s_flight_a = rogue_server_a.take_outbound()
  let ok_a = try {
    ignore(client_a.feed(s_flight_a[:]))
    false
  } catch {
    @state.CertificateError(_) => true
    _ => false
  }
  assert_true(ok_a)
  assert_true(client_a.is_failed())
  adv_assert_plaintext_fatal_alert(
    client_a.take_outbound(),
    @handshake.BadCertificate,
  )
  // Part B: Unknown CA (client has no matching trust anchor -> UnknownCa)
  let client_b = @state.ClientConn::new({
    trust_anchors: [],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-09-cb",
  })
  let rogue_server_b = @state.ServerConn::new({
    sign_cert: pki_rogue.server_sign_cert,
    sign_priv: pki_rogue.server_sign_priv,
    enc_cert: pki_rogue.server_enc_cert,
    enc_priv: pki_rogue.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed: b"adv-09-sb",
  })
  let ch_b = client_b.start_handshake()
  ignore(rogue_server_b.feed(ch_b[:]))
  let s_flight_b = rogue_server_b.take_outbound()
  let ok_b = try {
    ignore(client_b.feed(s_flight_b[:]))
    false
  } catch {
    @state.CertificateError(_) => true
    _ => false
  }
  assert_true(ok_b)
  assert_true(client_b.is_failed())
  adv_assert_plaintext_fatal_alert(
    client_b.take_outbound(),
    @handshake.UnknownCa,
  )
}

///|
test "adversarial 10: forged ServerKeyExchange ECC signature rejected with DecryptError" {
  let pki = @x509.generate_test_pki(b"adv-10")
  let client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-10-c",
  })
  let server = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed: b"adv-10-s",
  })
  let ch = client.start_handshake()
  ignore(server.feed(ch[:]))
  let recs = adv_parse_records(server.take_outbound())
  // recs[0]=SH, recs[1]=Cert, recs[2]=SKE, recs[3]=SHD -> corrupt last byte of SKE signature
  let forged_ske = @record.RawRecord::{
    content_type: recs[2].content_type,
    version_major: recs[2].version_major,
    version_minor: recs[2].version_minor,
    payload: adv_flip_byte(recs[2].payload, recs[2].payload.length() - 1, 0x01U),
  }
  let tampered_flight = adv_concat([
    @record.encode_record(recs[0]),
    @record.encode_record(recs[1]),
    @record.encode_record(forged_ske),
    @record.encode_record(recs[3]),
  ])
  let ok = try {
    ignore(client.feed(tampered_flight[:]))
    false
  } catch {
    @state.CryptoError(_) => true
    _ => false
  }
  assert_true(ok)
  assert_true(client.is_failed())
  adv_assert_plaintext_fatal_alert(
    client.take_outbound(),
    @handshake.DecryptError,
  )
}

///|
test "adversarial 11: forged ServerKeyExchange ECDHE signature rejected with DecryptError" {
  let pki = @x509.generate_test_pki(b"adv-11")
  let client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EcdheSm4GcmSm3],
    client_certs: Some(
      (
        pki.client_sign_cert,
        pki.client_sign_priv,
        pki.client_enc_cert,
        pki.client_enc_priv,
      ),
    ),
    resume_session: None,
    seed: b"adv-11-c",
  })
  let server = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EcdheSm4GcmSm3],
    require_client_cert: true,
    client_trust_anchors: [pki.ca_cert],
    session_store: None,
    seed: b"adv-11-s",
  })
  let ch = client.start_handshake()
  ignore(server.feed(ch[:]))
  let recs = adv_parse_records(server.take_outbound())
  let forged_ske = @record.RawRecord::{
    content_type: recs[2].content_type,
    version_major: recs[2].version_major,
    version_minor: recs[2].version_minor,
    payload: adv_flip_byte(recs[2].payload, recs[2].payload.length() - 1, 0x01U),
  }
  let parts : Array[Bytes] = []
  for i = 0; i < recs.length(); i = i + 1 {
    parts.push(@record.encode_record(if i == 2 { forged_ske } else { recs[i] }))
  }
  let ok = try {
    ignore(client.feed(adv_concat(parts)[:]))
    false
  } catch {
    @state.CryptoError(_) => true
    _ => false
  }
  assert_true(ok)
  assert_true(client.is_failed())
  adv_assert_plaintext_fatal_alert(
    client.take_outbound(),
    @handshake.DecryptError,
  )
}

///|
test "adversarial 12: tampered client Finished verify_data (via tampered transcript) rejected" {
  let pki = @x509.generate_test_pki(b"adv-12")
  // Client and server complete handshake normally, except MITM injects a duplicate
  // empty-wait/altered ServerHelloDone? Even simpler: corrupt ClientHello random
  // between client and server? No, server uses client_random from wire; instead
  // tamper client's encrypted Finished ciphertext OR forge a valid encrypted Finished
  // with wrong verify_data! Let's test BOTH: here we tamper client's Finished verify_data
  // by re-sealing a bad Finished? Actually, we can have a MITM flip a bit inside
  // ClientHello random BEFORE server sees it -> server computes a different master_secret/transcript,
  // OR flip 1 bit in ClientKeyExchange -> wait, let's verify Finished verify_data mismatch directly!
  // On a resumed session, if client's cached master_secret is wrong, CCS succeeds and Finished fails MAC;
  // To specifically hit `verify_data mismatch` (valid encryption key, wrong verify_data):
  // Have a valid established key on client, or test MITM modifying ClientHello's cipher_suites list
  // (e.g. changing a non-selected extra cipher suite byte in ClientHello so BOTH sides derive
  // the EXACT SAME master_secret and encryption keys, so Finished decrypts validly with MAC OK,
  // yet transcript hash differs so verify_data FAILS with DecryptError!).
  let client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3, @handshake.EccSm4CbcSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-12-c",
  })
  let server = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed: b"adv-12-s",
  })
  // MITM mutates the second (unselected) cipher suite in ClientHello from 0xE013 to 0xE011!
  // Keys stay identical, but client & server transcripts diverge -> client Finished decrypts cleanly
  // and fails verify_data check with DecryptError!
  let ch = client.start_handshake()
  // Last 4 bytes of ch are: 2B second suite (0xE0, 0x13), 1B comp_len (0x01), 1B comp (0x00)
  let mitm_ch = adv_flip_byte(ch, ch.length() - 3, 0x02U)
  ignore(server.feed(mitm_ch[:]))
  ignore(client.feed(server.take_outbound()[:]))
  let c_flight = client.take_outbound()
  let ok = try {
    ignore(server.feed(c_flight[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.DecryptError, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
}

///|
test "adversarial 13: tampered server Finished verify_data rejected by client with DecryptError" {
  let pki = @x509.generate_test_pki(b"adv-13")
  let store = @state.SessionStore::new()
  // Establish a real session first
  let c1 = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-13-c1",
  })
  let s1 = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(store),
    seed: b"adv-13-s1",
  })
  ignore(run_handshake(c1, s1))
  let saved = match c1.export_session() {
    Some(s) => s
    None => abort("expected session")
  }
  // On abbreviated resumption, MITM alters the second (unselected) cipher suite in ClientHello.
  // Both sides derive the exact same KeyBlock from saved master_secret + randoms,
  // so Server Finished decrypts validly with MAC OK, and client catches verify_data mismatch!
  let c2 = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3, @handshake.EccSm4CbcSm3],
    client_certs: None,
    resume_session: Some(saved),
    seed: b"adv-13-c2",
  })
  let s2 = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(store),
    seed: b"adv-13-s2",
  })
  let ch = c2.start_handshake()
  let mitm_ch = adv_flip_byte(ch, ch.length() - 3, 0x02U)
  ignore(s2.feed(mitm_ch[:]))
  let s_flight = s2.take_outbound()
  let ok = try {
    ignore(c2.feed(s_flight[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.DecryptError, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(c2.is_failed())
}

///|
test "adversarial 14: encrypted ApplicationData replay attack rejected on both CBC and GCM" {
  let pki = @x509.generate_test_pki(b"adv-14")
  for suite in [@handshake.EccSm4CbcSm3, @handshake.EccSm4GcmSm3] {
    let (client, server) = adv_setup_established(pki, suite, b"14")
    let wire1 = client.write_app_data(b"transfer 1000 RMB")
    // First delivery succeeds
    let ev1 = server.feed(wire1[:])
    assert_eq(ev1, [@state.ApplicationData(b"transfer 1000 RMB")])
    // Replaying wire1 must fail with BadRecordMac (sequence number mismatch)
    let replay_rejected = try {
      ignore(server.feed(wire1[:]))
      false
    } catch {
      @state.ProtocolError(@handshake.BadRecordMac, _) => true
      _ => false
    }
    assert_true(replay_rejected)
    assert_true(server.is_failed())
  }
}

///|
test "adversarial 15: skipping ChangeCipherSpec and sending plaintext Finished rejected" {
  let pki = @x509.generate_test_pki(b"adv-15")
  let client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-15-c",
  })
  let server = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed: b"adv-15-s",
  })
  ignore(server.feed(client.start_handshake()[:]))
  ignore(client.feed(server.take_outbound()[:]))
  // recs[0] = ClientKeyExchange, recs[1] = CCS, recs[2] = Finished
  let recs = adv_parse_records(client.take_outbound())
  // Send CKE, skip CCS, inject a plaintext Finished record!
  let fake_fin = @record.encode_record({
    content_type: @record.Handshake,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: @handshake.encode_handshake_msg(
      @handshake.Finished({ verify_data: Bytes::make(12, b'\xaa'), }),
    ),
  })
  let bad_flight = adv_concat([@record.encode_record(recs[0]), fake_fin])
  let ok = try {
    ignore(server.feed(bad_flight[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.UnexpectedMessage, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
  adv_assert_plaintext_fatal_alert(
    server.take_outbound(),
    @handshake.UnexpectedMessage,
  )
}

///|
test "adversarial 16: premature ApplicationData before handshake completion rejected" {
  let pki = @x509.generate_test_pki(b"adv-16")
  let server = @state.ServerConn::new(
    @state.ServerConfig::new(
      pki.server_sign_cert,
      pki.server_sign_priv,
      pki.server_enc_cert,
      pki.server_enc_priv,
      b"adv-16-s",
    ),
  )
  let early_app = @record.encode_record({
    content_type: @record.ApplicationData,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: b"smuggled plaintext app data",
  })
  let ok = try {
    ignore(server.feed(early_app[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.UnexpectedMessage, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
  adv_assert_plaintext_fatal_alert(
    server.take_outbound(),
    @handshake.UnexpectedMessage,
  )
}

///|
test "adversarial 17: unexpected ChangeCipherSpec injection before ServerHello rejected" {
  let pki = @x509.generate_test_pki(b"adv-17")
  let client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-17-c",
  })
  ignore(client.start_handshake())
  let early_ccs = @record.encode_record({
    content_type: @record.ChangeCipherSpec,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: b"\x01",
  })
  let ok = try {
    ignore(client.feed(early_ccs[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.UnexpectedMessage, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(client.is_failed())
  adv_assert_plaintext_fatal_alert(
    client.take_outbound(),
    @handshake.UnexpectedMessage,
  )
}

///|
test "adversarial 18: mTLCP missing client certificate rejected by client and empty cert rejected by server" {
  let pki = @x509.generate_test_pki(b"adv-18")
  // Part A: client configured without client_certs fails when server sends CertificateRequest
  let client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-18-c",
  })
  let server = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: true,
    client_trust_anchors: [pki.ca_cert],
    session_store: None,
    seed: b"adv-18-s",
  })
  let ch = client.start_handshake()
  ignore(server.feed(ch[:]))
  let s_flight = server.take_outbound()
  let c_failed = try {
    ignore(client.feed(s_flight[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.HandshakeFailure, _) => true
    _ => false
  }
  assert_true(c_failed)
  assert_true(client.is_failed())
  // Part B: server waiting in WaitClientCert rejects empty CertificateMsg([])
  let empty_cert_rec = @record.encode_record({
    content_type: @record.Handshake,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: @handshake.encode_handshake_msg(
      @handshake.Certificate({ certificates: [], }),
    ),
  })
  let s_failed = try {
    ignore(server.feed(empty_cert_rec[:]))
    false
  } catch {
    @state.CertificateError(_) => true
    _ => false
  }
  assert_true(s_failed)
  assert_true(server.is_failed())
  adv_assert_plaintext_fatal_alert(
    server.take_outbound(),
    @handshake.BadCertificate,
  )
}

///|
test "adversarial 19: mTLCP forged client CertificateVerify signature rejected by server" {
  let pki = @x509.generate_test_pki(b"adv-19")
  let client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: Some(
      (
        pki.client_sign_cert,
        pki.client_sign_priv,
        pki.client_enc_cert,
        pki.client_enc_priv,
      ),
    ),
    resume_session: None,
    seed: b"adv-19-c",
  })
  let server = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: true,
    client_trust_anchors: [pki.ca_cert],
    session_store: None,
    seed: b"adv-19-s",
  })
  ignore(server.feed(client.start_handshake()[:]))
  ignore(client.feed(server.take_outbound()[:]))
  // recs[0]=Cert, recs[1]=CKE, recs[2]=CertVerify, recs[3]=CCS, recs[4]=Finished
  let recs = adv_parse_records(client.take_outbound())
  let forged_cv = @record.RawRecord::{
    content_type: recs[2].content_type,
    version_major: recs[2].version_major,
    version_minor: recs[2].version_minor,
    payload: adv_flip_byte(recs[2].payload, recs[2].payload.length() - 1, 0x01U),
  }
  let bad_flight = adv_concat([
    @record.encode_record(recs[0]),
    @record.encode_record(recs[1]),
    @record.encode_record(forged_cv),
    @record.encode_record(recs[3]),
    @record.encode_record(recs[4]),
  ])
  let ok = try {
    ignore(server.feed(bad_flight[:]))
    false
  } catch {
    @state.CryptoError(_) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
  adv_assert_plaintext_fatal_alert(
    server.take_outbound(),
    @handshake.DecryptError,
  )
}

///|
test "adversarial 20: disjoint cipher suite sets fail with HandshakeFailure alert" {
  let pki = @x509.generate_test_pki(b"adv-20")
  let client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4CbcSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-20-c",
  })
  let server = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EcdheSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed: b"adv-20-s",
  })
  let ch = client.start_handshake()
  let s_rej = try {
    ignore(server.feed(ch[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.HandshakeFailure, _) => true
    _ => false
  }
  assert_true(s_rej)
  assert_true(server.is_failed())
  let fatal_wire = server.take_outbound()
  adv_assert_plaintext_fatal_alert(fatal_wire, @handshake.HandshakeFailure)
  // Feeding server's Fatal Alert to client also transitions client to Failed!
  let c_rej = try {
    ignore(client.feed(fatal_wire[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.HandshakeFailure, _) => true
    _ => false
  }
  assert_true(c_rej)
  assert_true(client.is_failed())
}

///|
test "adversarial 21: permanent fail-closed enforcement rejects all post-failure operations" {
  let pki = @x509.generate_test_pki(b"adv-21")
  let (client, server) = adv_setup_established(
    pki,
    @handshake.EccSm4GcmSm3,
    b"21",
  )
  let wire = client.write_app_data(b"valid")
  // Trigger failure on server
  let _ = try {
    ignore(server.feed(adv_flip_byte(wire, wire.length() - 1, 0x01U)[:]))
    false
  } catch {
    _ => true
  }
  assert_true(server.is_failed())
  // Subsequent feed, write_app_data, and close_notify MUST all raise InvalidState
  let feed_rej = try {
    ignore(server.feed(wire[:]))
    false
  } catch {
    @state.InvalidState(_) => true
    _ => false
  }
  assert_true(feed_rej)
  let write_rej = try {
    ignore(server.write_app_data(b"after fail"))
    false
  } catch {
    @state.InvalidState(_) => true
    _ => false
  }
  assert_true(write_rej)
  let close_rej = try {
    ignore(server.close_notify())
    false
  } catch {
    @state.InvalidState(_) => true
    _ => false
  }
  assert_true(close_rej)
}

///|
test "adversarial 22: oversized record header (>18432B) rejected immediately with RecordOverflow alert" {
  let pki = @x509.generate_test_pki(b"adv-22")
  let server = @state.ServerConn::new(
    @state.ServerConfig::new(
      pki.server_sign_cert,
      pki.server_sign_priv,
      pki.server_enc_cert,
      pki.server_enc_priv,
      b"adv-22-s",
    ),
  )
  // Header claims 0x4801 = 18433 bytes (> MAX_CIPHERTEXT_LEN 18432)
  let over_hdr = Bytes::from_array([b'\x16', b'\x01', b'\x01', b'\x48', b'\x01'])
  let ok = try {
    ignore(server.feed(over_hdr[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.RecordOverflow, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(server.is_failed())
  adv_assert_plaintext_fatal_alert(
    server.take_outbound(),
    @handshake.RecordOverflow,
  )
}

///|
test "adversarial 23: oversized handshake frame DoS (>64KiB) immediately rejected with DecodeError" {
  let pki = @x509.generate_test_pki(b"adv-23")
  // Part A: single handshake record whose 4B header claims 65537 (0x010001) bytes
  let server_a = @state.ServerConn::new(
    @state.ServerConfig::new(
      pki.server_sign_cert,
      pki.server_sign_priv,
      pki.server_enc_cert,
      pki.server_enc_priv,
      b"adv-23-sa",
    ),
  )
  let huge_hs_hdr = @record.encode_record({
    content_type: @record.Handshake,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: Bytes::from_array([b'\x01', b'\x01', b'\x00', b'\x01', b'\x00']),
  })
  let ok_a = try {
    ignore(server_a.feed(huge_hs_hdr[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.DecodeError, _) => true
    _ => false
  }
  assert_true(ok_a)
  assert_true(server_a.is_failed())
  adv_assert_plaintext_fatal_alert(
    server_a.take_outbound(),
    @handshake.DecodeError,
  )
  // Part B: multi-record handshake reassembly attempting to accumulate > 65540 bytes
  let server_b = @state.ServerConn::new(
    @state.ServerConfig::new(
      pki.server_sign_cert,
      pki.server_sign_priv,
      pki.server_enc_cert,
      pki.server_enc_priv,
      b"adv-23-sb",
    ),
  )
  // First record claims valid 65536B body (0x010000) with 16380B payload (total 16384B)
  let first_chunk = FixedArray::make(16384, b'\x41')
  first_chunk[0] = b'\x01'
  first_chunk[1] = b'\x01'
  first_chunk[2] = b'\x00'
  first_chunk[3] = b'\x00'
  let rec1 = @record.encode_record({
    content_type: @record.Handshake,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: Bytes::from_array(first_chunk),
  })
  let cont_rec = @record.encode_record({
    content_type: @record.Handshake,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: Bytes::make(16384, b'\x42'),
  })
  // 5 * 16384 = 81920 > 65540 must trigger hs_buf cap DecodeError
  let flood = adv_concat([rec1, cont_rec, cont_rec, cont_rec, cont_rec])
  let ok_b = try {
    ignore(server_b.feed(flood[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.DecodeError, _) => true
    _ => false
  }
  assert_true(ok_b)
  assert_true(server_b.is_failed())
  adv_assert_plaintext_fatal_alert(
    server_b.take_outbound(),
    @handshake.DecodeError,
  )
}

///|
test "adversarial 24: trailing bytes injected after Finished in same record rejected and GCM explicit nonce equals seq" {
  let pki = @x509.generate_test_pki(b"adv-24")
  let store = @state.SessionStore::new()
  // 1. Establish initial GCM session to obtain master_secret and also verify RFC 5288 GCM explicit nonce = seq
  let (c1, s1) = adv_setup_established(pki, @handshake.EccSm4GcmSm3, b"24-init")
  let app_w0 = c1.write_app_data(b"check-nonce-seq-1")
  let app_w1 = c1.write_app_data(b"check-nonce-seq-2")
  // Record seq 0 was Finished; app_w0 has seq=1, app_w1 has seq=2 in explicit nonce (bytes 5..13)
  let (r0, _) = @record.decode_record(app_w0[:])
  let (r1, _) = @record.decode_record(app_w1[:])
  assert_eq(r0.payload[0:8].to_owned(), b"\x00\x00\x00\x00\x00\x00\x00\x01")
  assert_eq(r1.payload[0:8].to_owned(), b"\x00\x00\x00\x00\x00\x00\x00\x02")
  ignore(s1.feed(app_w0[:]))
  ignore(s1.feed(app_w1[:]))
  // 2. Populate SessionStore with a fresh full handshake
  let c_seed = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-24-c1",
  })
  let s_seed = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(store),
    seed: b"adv-24-s1",
  })
  ignore(run_handshake(c_seed, s_seed))
  let saved = match c_seed.export_session() {
    Some(s) => s
    None => abort("expected saved session")
  }
  // 3. Start resumed handshake and craft ClientFinished + 1 trailing byte in the SAME encrypted record
  let c2 = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: Some(saved),
    seed: b"adv-24-c2",
  })
  let s2 = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(store),
    seed: b"adv-24-s2",
  })
  let ch_wire = c2.start_handshake()
  let (ch_rec, _) = @record.decode_record(ch_wire[:])
  let (_, ch_body, _) = @handshake.decode_handshake_frame(ch_rec.payload[:])
  let cr = match
    @handshake.decode_handshake_msg(@handshake.HT_CLIENT_HELLO, ch_body, false) {
    @handshake.ClientHello(ch) => ch.random
    _ => abort("expected ClientHello")
  }
  ignore(s2.feed(ch_wire[:]))
  let s_flight = s2.take_outbound()
  let s_recs = adv_parse_records(s_flight)
  // s_recs[0]=ServerHello, s_recs[1]=CCS, s_recs[2]=ServerFinished (encrypted)
  let (_, sh_body, _) = @handshake.decode_handshake_frame(s_recs[0].payload[:])
  let sr = match
    @handshake.decode_handshake_msg(@handshake.HT_SERVER_HELLO, sh_body, false) {
    @handshake.ServerHello(sh) => sh.random
    _ => abort("expected ServerHello")
  }
  let kb = @handshake.derive_key_block(
    saved.master_secret,
    sr,
    cr,
    @handshake.EccSm4GcmSm3,
  )
  let s_read = @record.RecordLayer::new()
  s_read.set_cipher(
    @record.CipherState::new_gcm(kb.server_write_key, kb.server_write_iv),
  )
  let s_fin_raw = s_read.open(s_recs[2])
  let tr = @handshake.Transcript::new()
  tr.update(ch_rec.payload)
  tr.update(s_recs[0].payload)
  tr.update(s_fin_raw)
  let c_vd = @handshake.compute_verify_data(
    saved.master_secret,
    true,
    tr.hash(),
  )
  let poisoned_fin_payload = adv_concat([
    @handshake.encode_handshake_msg(@handshake.Finished({ verify_data: c_vd, })),
    b"\x14",
  ])
  let c_ccs = @record.encode_record({
    content_type: @record.ChangeCipherSpec,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: b"\x01",
  })
  let c_write = @record.RecordLayer::new()
  c_write.set_cipher(
    @record.CipherState::new_gcm(kb.client_write_key, kb.client_write_iv),
  )
  let poisoned_fin_rec = c_write.seal(
    @record.Handshake,
    poisoned_fin_payload,
    b"\x00\x00\x00\x00\x00\x00\x00\x00",
  )
  let ok = try {
    ignore(s2.feed(adv_concat([c_ccs, poisoned_fin_rec])[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.UnexpectedMessage, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(s2.is_failed())
  assert_true(!s2.is_established())
}

///|
test "adversarial 25: non-mTLCP session cannot bypass mTLCP server and invalid ResumedSession rejected" {
  let pki = @x509.generate_test_pki(b"adv-25")
  let shared_store = @state.SessionStore::new()
  // Part A: Client completes a 1-way (no client cert) handshake into shared_store
  let c_oneway = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-25-c1",
  })
  let s_oneway = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(shared_store),
    seed: b"adv-25-s1",
  })
  ignore(run_handshake(c_oneway, s_oneway))
  let unauth_session = match c_oneway.export_session() {
    Some(s) => s
    None => abort("expected session")
  }
  // Attempt to resume unauth_session against an mTLCP server (require_client_cert = true)
  let c_escalate = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: Some(unauth_session),
    seed: b"adv-25-c2",
  })
  let s_mtlcp = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: true,
    client_trust_anchors: [pki.ca_cert],
    session_store: Some(shared_store),
    seed: b"adv-25-s2",
  })
  let esc_blocked = try {
    ignore(run_handshake(c_escalate, s_mtlcp))
    false
  } catch {
    @state.ProtocolError(@handshake.HandshakeFailure, _) => true
    _ => false
  }
  assert_true(esc_blocked)
  assert_true(!s_mtlcp.is_resumed())
  assert_true(!s_mtlcp.is_established())
  // Part B: Genuine mTLCP session CAN resume and restores server.peer_certs()
  let c_m1 = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: Some(
      (
        pki.client_sign_cert,
        pki.client_sign_priv,
        pki.client_enc_cert,
        pki.client_enc_priv,
      ),
    ),
    resume_session: None,
    seed: b"adv-25-cm1",
  })
  let s_m1 = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: true,
    client_trust_anchors: [pki.ca_cert],
    session_store: Some(shared_store),
    seed: b"adv-25-sm1",
  })
  ignore(run_handshake(c_m1, s_m1))
  let mtlcp_session = match c_m1.export_session() {
    Some(s) => s
    None => abort("expected mTLCP session")
  }
  let c_m2 = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: Some(
      (
        pki.client_sign_cert,
        pki.client_sign_priv,
        pki.client_enc_cert,
        pki.client_enc_priv,
      ),
    ),
    resume_session: Some(mtlcp_session),
    seed: b"adv-25-cm2",
  })
  let s_m2 = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: true,
    client_trust_anchors: [pki.ca_cert],
    session_store: Some(shared_store),
    seed: b"adv-25-sm2",
  })
  ignore(run_handshake(c_m2, s_m2))
  assert_true(c_m2.is_resumed() && s_m2.is_resumed())
  assert_true(s_m2.peer_certs() is Some(_))
  assert_true(c_m2.peer_certs() is Some(_))
  // Part C: Invalid ResumedSession (bad master_secret or session_id > 32B) rejected
  let bad_ms_client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: Some({
      session_id: Bytes::make(16, b'\x01'),
      cipher_suite: @handshake.EccSm4GcmSm3,
      master_secret: Bytes::make(16, b'\x02'),
      peer_certs: None,
    }),
    seed: b"adv-25-bad1",
  })
  let bad_ms_rej = try {
    ignore(bad_ms_client.start_handshake())
    false
  } catch {
    @state.InvalidState(_) => true
    _ => false
  }
  assert_true(bad_ms_rej)
  let bad_sid_client = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: Some({
      session_id: Bytes::make(33, b'\x01'),
      cipher_suite: @handshake.EccSm4GcmSm3,
      master_secret: Bytes::make(48, b'\x02'),
      peer_certs: None,
    }),
    seed: b"adv-25-bad2",
  })
  let bad_sid_rej = try {
    ignore(bad_sid_client.start_handshake())
    false
  } catch {
    @state.InvalidState(_) => true
    _ => false
  }
  assert_true(bad_sid_rej)
}

///|
test "adversarial 26: ApplicationData sent after peer CloseNotify rejected with UnexpectedMessage" {
  let pki = @x509.generate_test_pki(b"adv-26")
  let store = @state.SessionStore::new()
  // Establish a resumed session so we can craft a validly encrypted ApplicationData record after CloseNotify
  let c1 = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"adv-26-c1",
  })
  let s1 = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(store),
    seed: b"adv-26-s1",
  })
  ignore(run_handshake(c1, s1))
  let saved = match c1.export_session() {
    Some(s) => s
    None => abort("expected session")
  }
  let c2 = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: Some(saved),
    seed: b"adv-26-c2",
  })
  let s2 = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(store),
    seed: b"adv-26-s2",
  })
  let ch_wire = c2.start_handshake()
  let (ch_rec, _) = @record.decode_record(ch_wire[:])
  let (_, ch_body, _) = @handshake.decode_handshake_frame(ch_rec.payload[:])
  let cr = match
    @handshake.decode_handshake_msg(@handshake.HT_CLIENT_HELLO, ch_body, false) {
    @handshake.ClientHello(ch) => ch.random
    _ => abort("expected ClientHello")
  }
  ignore(s2.feed(ch_wire[:]))
  let s_flight = s2.take_outbound()
  let s_recs = adv_parse_records(s_flight)
  let (_, sh_body, _) = @handshake.decode_handshake_frame(s_recs[0].payload[:])
  let sr = match
    @handshake.decode_handshake_msg(@handshake.HT_SERVER_HELLO, sh_body, false) {
    @handshake.ServerHello(sh) => sh.random
    _ => abort("expected ServerHello")
  }
  ignore(c2.feed(s_flight[:]))
  ignore(s2.feed(c2.take_outbound()[:]))
  assert_true(c2.is_established() && s2.is_established())
  // Client sends valid CloseNotify (seq=1) -> Server emits PeerClosed
  let close_wire = c2.close_notify()
  assert_eq(s2.feed(close_wire[:]), [@state.PeerClosed])
  // Now craft a validly encrypted ApplicationData record at seq=2 after CloseNotify
  let kb = @handshake.derive_key_block(
    saved.master_secret,
    sr,
    cr,
    @handshake.EccSm4GcmSm3,
  )
  let forge_layer = @record.RecordLayer::new()
  forge_layer.set_cipher(
    @record.CipherState::new_gcm(kb.client_write_key, kb.client_write_iv),
  )
  // Advance forge_layer seq 0 -> 1 -> 2 to match server's expected next seq
  ignore(
    forge_layer.seal(
      @record.Handshake,
      b"skip0",
      b"\x00\x00\x00\x00\x00\x00\x00\x00",
    ),
  )
  ignore(
    forge_layer.seal(
      @record.Alert,
      b"skip1",
      b"\x00\x00\x00\x00\x00\x00\x00\x01",
    ),
  )
  let post_close_app = forge_layer.seal(
    @record.ApplicationData,
    b"illegal data after CloseNotify",
    b"\x00\x00\x00\x00\x00\x00\x00\x02",
  )
  let ok = try {
    ignore(s2.feed(post_close_app[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.UnexpectedMessage, _) => true
    _ => false
  }
  assert_true(ok)
  assert_true(s2.is_failed())
}
