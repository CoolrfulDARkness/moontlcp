///|
/// External published-package smoke tests consuming `CoolrfulDARkness/moontlcp`
/// directly from `mooncakes.io`.

///|
test "published SM3, SM4-GCM, and SM2 primitives work end-to-end" {
  // 1. SM3 GB/T 32905-2016 standard test vector ("abc")
  let digest = @moontlcp.sm3_hash(b"abc")
  assert_eq(digest.length(), 32)
  assert_eq(digest[0], b'\x66')
  assert_eq(digest[1], b'\xc7')
  assert_eq(digest[2], b'\xf0')
  assert_eq(digest[3], b'\xf4')
  let mac = @moontlcp.hmac_sm3(b"consumer-hmac-key", b"consumer-msg")
  assert_eq(mac.length(), 32)
  // 2. SM4-GCM AEAD round-trip
  let key = Bytes::make(16, b'\x11')
  let iv = Bytes::make(12, b'\x22')
  let aad = b"moontlcp-consumer-aad"
  let plaintext = b"Hello published SM4-GCM!"
  let (ct, tag) = @moontlcp.sm4_gcm_encrypt(key, iv, aad, plaintext)
  assert_eq(tag.length(), 16)
  let dec = @moontlcp.sm4_gcm_decrypt(key, iv, aad, ct, tag)
  assert_eq(dec, plaintext)
  // 3. SM2 Sign/Verify and ASN.1 Encrypt/Decrypt
  let pki = @moontlcp.generate_test_pki(b"consumer-sm2-seed")
  let sm2_id = b"1234567812345678"
  let sig = @moontlcp.sm2_sign_der(pki.server_sign_priv, sm2_id, plaintext)
  assert_true(
    @moontlcp.sm2_verify_der(
      pki.server_sign_cert.public_key,
      sm2_id,
      plaintext,
      sig,
    ),
  )
  assert_true(
    !@moontlcp.sm2_verify_der(
      pki.server_sign_cert.public_key,
      sm2_id,
      b"tampered",
      sig,
    ),
  )
  let sm2_ct = @moontlcp.sm2_encrypt_asn1(
    pki.server_enc_cert.public_key,
    plaintext,
    b"consumer-enc-seed",
  )
  assert_eq(@moontlcp.sm2_decrypt_asn1(pki.server_enc_priv, sm2_ct), plaintext)
}

///|
test "published TLCP 1.1 handshake config and bidirectional encrypted transport" {
  let pki = @moontlcp.generate_test_pki(b"consumer-tlcp-seed")
  let client_cfg = @state.ClientConfig::new(
    [pki.ca_cert],
    b"consumer-client-seed",
  )
  let server_cfg = @state.ServerConfig::new(
    pki.server_sign_cert,
    pki.server_sign_priv,
    pki.server_enc_cert,
    pki.server_enc_priv,
    b"consumer-server-seed",
  )
  let client = @moontlcp.new_client(client_cfg)
  let server = @moontlcp.new_server(server_cfg)
  let (c_bytes, s_bytes) = @moontlcp.run_handshake_loop(client, server)
  assert_true(c_bytes > 0 && s_bytes > 0)
  assert_true(client.is_established() && server.is_established())
  let msg = b"hello from published mooncakes.io consumer!"
  let wire = client.write_app_data(msg)
  let events = server.feed(wire[:])
  assert_eq(events, [@state.ApplicationData(msg)])
}

///|
test "published SM9 BN256 KGC key extraction and Sign/Verify round-trip" {
  let sign_master = @sm9.sign_master_from_seed(b"consumer-sm9-kgc-seed")
  let user_id = b"alice@moontlcp.example"
  let user_priv = match @sm9.extract_sign_key(sign_master, user_id[:]) {
    Ok(k) => k
    Err(e) => abort("extract_sign_key failed: " + e)
  }
  let msg = b"SM9 consumer smoke verification message"
  let sig = match @sm9.sign(sign_master.public_key(), user_priv, msg[:]) {
    Ok(s) => s
    Err(e) => abort("sm9 sign failed: " + e)
  }
  assert_true(@sm9.verify(sign_master.public_key(), user_id[:], msg[:], sig))
  assert_true(
    !@sm9.verify(sign_master.public_key(), user_id[:], b"forged"[:], sig),
  )
}

///|
test "published stateless wire dissectors inspect_record and inspect_handshake" {
  let pki = @moontlcp.generate_test_pki(b"consumer-inspect-seed")
  let client = @moontlcp.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"consumer-inspect-c",
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
    seed: b"consumer-inspect-s",
  })
  // Flight 1: ClientHello via inspect_record + inspect_handshake
  let flight1 = client.start_handshake()
  let rec1 = @moontlcp.inspect_record(flight1[:])
  assert_eq(rec1.content_type_name, "Handshake")
  assert_eq(rec1.is_tlcp_1_1, true)
  let ch_payload = flight1[rec1.payload_offset:rec1.payload_offset +
    rec1.payload_len]
  let ch = @moontlcp.inspect_handshake(ch_payload)
  assert_eq(ch.msg_type_name, "ClientHello")
  assert_eq(ch.protocol_version, 0x0101U)
  assert_eq(ch.cipher_suites, [0xE053U])
  // Flight 2: ServerHello + dual Certificate stream via inspect_record_stream
  ignore(server.feed(flight1[:]))
  let flight2 = server.take_outbound()
  let f2_recs = @moontlcp.inspect_record_stream(flight2[:])
  assert_true(f2_recs.length() >= 4)
  let mut saw_server_hello = false
  let mut saw_dual_cert = false
  for r in f2_recs {
    assert_eq(r.content_type_name, "Handshake")
    assert_eq(r.is_tlcp_1_1, true)
    let payload = flight2[r.payload_offset:r.payload_offset + r.payload_len]
    let mut off = 0
    while off < payload.length() {
      let hs = @moontlcp.inspect_handshake(payload[off:])
      if hs.msg_type_name == "ServerHello" {
        assert_eq(hs.selected_suite, Some(0xE053U))
        saw_server_hello = true
      }
      if hs.msg_type_name == "Certificate" {
        assert_eq(hs.cert_count, 2)
        saw_dual_cert = true
      }
      off = off + hs.total_wire_len
    }
  }
  assert_true(saw_server_hello && saw_dual_cert)
  // Stateless alert inspection
  let (lvl, desc, name) = @moontlcp.inspect_alert(b"\x02\x46"[:])
  assert_eq(lvl, b'\x02')
  assert_eq(desc, b'\x46')
  assert_eq(name, "ProtocolVersion")
}
