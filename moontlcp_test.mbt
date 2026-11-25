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
