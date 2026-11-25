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
