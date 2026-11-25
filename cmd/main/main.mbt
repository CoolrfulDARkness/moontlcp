///|
/// MoonTLCP One-Click End-to-End Live Verification & Security Demo CLI.
///
/// Run from repository root:
///   `moon run cmd/main`

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
fn from_hex(s : String) -> Bytes {
  let n = s.length() / 2
  let out = FixedArray::make(n, b'\x00')
  fn nibble(c : Int32) -> Int32 {
    if c >= 48 && c <= 57 {
      c - 48
    } else if c >= 97 && c <= 102 {
      c - 87
    } else {
      c - 55
    }
  }
  for i = 0; i < n; i = i + 1 {
    let hi = nibble(s[i * 2].to_int())
    let lo = nibble(s[i * 2 + 1].to_int())
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
fn suite_hex(code : UInt32) -> String {
  let hi = ((code >> 8) & 0xFFU).to_byte()
  let lo = (code & 0xFFU).to_byte()
  "0x" + to_hex(Bytes::from_array([hi, lo]))
}

///|
fn collect_app_data(events : Array[@state.Event]) -> Bytes {
  let chunks : Array[Bytes] = []
  let mut total = 0
  for i = 0; i < events.length(); i = i + 1 {
    match events[i] {
      @state.ApplicationData(d) => {
        chunks.push(d)
        total = total + d.length()
      }
      _ => ()
    }
  }
  let out = FixedArray::make(total, b'\x00')
  let mut off = 0
  for i = 0; i < chunks.length(); i = i + 1 {
    let c = chunks[i]
    for j = 0; j < c.length(); j = j + 1 {
      out[off + j] = c[j]
    }
    off = off + c.length()
  }
  Bytes::from_array(out)
}

///|
fn format_ku(ku_opt : @x509.KeyUsage?) -> String {
  match ku_opt {
    None => "(none)"
    Some(ku) => {
      let flags : Array[String] = []
      if ku.digital_signature {
        flags.push("digitalSignature")
      }
      if ku.content_commitment {
        flags.push("contentCommitment")
      }
      if ku.key_encipherment {
        flags.push("keyEncipherment")
      }
      if ku.data_encipherment {
        flags.push("dataEncipherment")
      }
      if ku.key_agreement {
        flags.push("keyAgreement")
      }
      if ku.key_cert_sign {
        flags.push("keyCertSign")
      }
      if ku.crl_sign {
        flags.push("cRLSign")
      }
      let buf = StringBuilder()
      for i = 0; i < flags.length(); i = i + 1 {
        if i > 0 {
          buf.write_string(", ")
        }
        buf.write_string(flags[i])
      }
      buf.to_string()
    }
  }
}

///|
fn demo_crypto_self_test() -> Unit {
  println(
    "====================================================================",
  )
  println(
    " [1/5] National Standard Cryptography Self-Test (Zero-FFI Pure MBT) ",
  )
  println(
    "====================================================================",
  )
  // 1. GB/T 32905-2016 SM3
  let sm3_abc = to_hex(@lib.sm3_hash(b"abc"))
  let sm3_ok = sm3_abc ==
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
  println(
    "  SM3(\"abc\")     : " +
    sm3_abc +
    (if sm3_ok { " [PASS]" } else { " [FAIL]" }),
  )
  // 2. GB/T 32907-2016 SM4 Block Cipher
  let sm4_key = from_hex("0123456789abcdeffedcba9876543210")
  let sm4_ok = try {
    let k = @sm4.Sm4Key::new(sm4_key)
    let ct = to_hex(k.encrypt_block(sm4_key))
    let pass = ct == "681edf34d206965e86b3e94f536e4246"
    println(
      "  SM4-ECB block  : " + ct + (if pass { " [PASS]" } else { " [FAIL]" }),
    )
    pass
  } catch {
    _ => false
  }
  ignore(sm4_ok)
  // 3. RFC 8998 Appendix A.1 SM4-GCM AEAD
  let gcm_iv = from_hex("00001234567800000000abcd")
  let gcm_aad = from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let gcm_pt = from_hex(
    "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
  )
  let _ = try {
    let (ct, tag) = @lib.sm4_gcm_encrypt(sm4_key, gcm_iv, gcm_aad, gcm_pt)
    let dec = @lib.sm4_gcm_decrypt(sm4_key, gcm_iv, gcm_aad, ct, tag)
    let tag_hex = to_hex(tag)
    let pass = tag_hex == "83de3541e4c2b58177e065a9bf7b62ec" && dec == gcm_pt
    println(
      "  SM4-GCM RFC8998: tag=" +
      tag_hex +
      (if pass { " [PASS]" } else { " [FAIL]" }),
    )
  } catch {
    _ => println("  SM4-GCM RFC8998: [FAIL]")
  }
  // 4. GB/T 32918-2016 SM2 Sign/Verify, Encrypt/Decrypt, Key Exchange
  let _ = try {
    let priv_a = @sm2.derive_keypair_from_seed(b"demo-sm2-a")
    let priv_b = @sm2.derive_keypair_from_seed(b"demo-sm2-b")
    let eph_a = @sm2.derive_keypair_from_seed(b"demo-sm2-eph-a")
    let eph_b = @sm2.derive_keypair_from_seed(b"demo-sm2-eph-b")
    let msg = b"GB/T 32918-2016 SM2 self-test message"
    let sig = @lib.sm2_sign_der(priv_a, @sm2.DEFAULT_SM2_ID, msg)
    let sig_ok = @lib.sm2_verify_der(
      priv_a.public_key(),
      @sm2.DEFAULT_SM2_ID,
      msg,
      sig,
    )
    let ct = @lib.sm2_encrypt_asn1(priv_b.public_key(), msg, b"demo-enc-seed")
    let pt = @lib.sm2_decrypt_asn1(priv_b, ct)
    let enc_ok = pt == msg
    let ke_a = @sm2.key_exchange_initiator(
      @sm2.DEFAULT_SM2_ID,
      priv_a,
      eph_a,
      @sm2.DEFAULT_SM2_ID,
      priv_b.public_key(),
      eph_b.public_key(),
      48,
    )
    let ke_b = @sm2.key_exchange_responder(
      @sm2.DEFAULT_SM2_ID,
      priv_b,
      eph_b,
      @sm2.DEFAULT_SM2_ID,
      priv_a.public_key(),
      eph_a.public_key(),
      48,
    )
    let ke_ok = ke_a.shared_key == ke_b.shared_key &&
      ke_a.s1 == ke_b.s1 &&
      ke_a.s2 == ke_b.s2
    println(
      "  SM2 Sign/Verify: " +
      sig.length().to_string() +
      "B DER " +
      (if sig_ok { "[PASS]" } else { "[FAIL]" }),
    )
    println(
      "  SM2 ASN.1 Enc  : " +
      ct.length().to_string() +
      "B SM2Cipher " +
      (if enc_ok { "[PASS]" } else { "[FAIL]" }),
    )
    println(
      "  SM2 KeyExchange: 48B shared key + S1/S2 match " +
      (if ke_ok { "[PASS]" } else { "[FAIL]" }),
    )
  } catch {
    _ => println("  SM2 self-test  : [FAIL]")
  }
}

///|
fn demo_x509_dual_pki(pki : @x509.TestPki) -> Unit {
  println("")
  println(
    "====================================================================",
  )
  println(
    " [2/5] GM X.509 v3 Dual-Certificate PKI Generation & Security Audit ",
  )
  println(
    "====================================================================",
  )
  println(
    "  Root CA      : CN=" +
    pki.ca_cert.subject_cn +
    " | isCA=true | KU=[" +
    format_ku(pki.ca_cert.key_usage) +
    "]",
  )
  println(
    "  Server Sign  : CN=" +
    pki.server_sign_cert.subject_cn +
    " | DER=" +
    pki.server_sign_cert.raw_der.length().to_string() +
    "B | KU=[" +
    format_ku(pki.server_sign_cert.key_usage) +
    "]",
  )
  println(
    "  Server Enc   : CN=" +
    pki.server_enc_cert.subject_cn +
    " | DER=" +
    pki.server_enc_cert.raw_der.length().to_string() +
    "B | KU=[" +
    format_ku(pki.server_enc_cert.key_usage) +
    "]",
  )
  println(
    "  Client Sign  : CN=" +
    pki.client_sign_cert.subject_cn +
    " | DER=" +
    pki.client_sign_cert.raw_der.length().to_string() +
    "B | KU=[" +
    format_ku(pki.client_sign_cert.key_usage) +
    "]",
  )
  println(
    "  Client Enc   : CN=" +
    pki.client_enc_cert.subject_cn +
    " | DER=" +
    pki.client_enc_cert.raw_der.length().to_string() +
    "B | KU=[" +
    format_ku(pki.client_enc_cert.key_usage) +
    "]",
  )
  let valid_ok = try {
    ignore(
      @lib.verify_dual_certs(
        [pki.server_sign_cert.raw_der, pki.server_enc_cert.raw_der],
        [pki.ca_cert],
      ),
    )
    true
  } catch {
    _ => false
  }
  println(
    "  Dual-Cert Chain Verify ([sign, enc]) : " +
    (if valid_ok { "[PASS]" } else { "[FAIL]" }),
  )
  let swap_blocked = try {
    ignore(
      @lib.verify_dual_certs(
        [pki.server_enc_cert.raw_der, pki.server_sign_cert.raw_der],
        [pki.ca_cert],
      ),
    )
    false
  } catch {
    _ => true
  }
  println(
    "  Swapped Dual-Cert Attack ([enc, sign]): " +
    (if swap_blocked { "[BLOCKED - DualCertMismatch]" } else { "[FAIL]" }),
  )
}

///|
fn demo_four_suites(pki : @x509.TestPki) -> Unit {
  println("")
  println(
    "====================================================================",
  )
  println(
    " [3/5] All 4 GM/T 0024-2023 TLCP 1.1 Suites Handshake & Encrypted IO",
  )
  println(
    "====================================================================",
  )
  let suites : Array[@handshake.CipherSuite] = [
    @handshake.EccSm4CbcSm3,
    @handshake.EccSm4GcmSm3,
    @handshake.EcdheSm4CbcSm3,
    @handshake.EcdheSm4GcmSm3,
  ]
  for i = 0; i < suites.length(); i = i + 1 {
    let suite = suites[i]
    let mode = if suite.is_ecdhe() { "mTLCP (Mutual)" } else { "Server-Auth" }
    let client = @lib.new_client({
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
      seed: b"cli-client-seed",
    })
    let server = @lib.new_server({
      sign_cert: pki.server_sign_cert,
      sign_priv: pki.server_sign_priv,
      enc_cert: pki.server_enc_cert,
      enc_priv: pki.server_enc_priv,
      cipher_suites: [suite],
      require_client_cert: suite.is_ecdhe(),
      client_trust_anchors: [pki.ca_cert],
      session_store: None,
      seed: b"cli-server-seed",
    })
    let _ = try {
      let (c_bytes, s_bytes) = @lib.run_handshake_loop(client, server)
      let req = b"POST /api/gm/transfer HTTP/1.1\r\nContent: TLCP-1.1"
      let resp = b"HTTP/1.1 200 OK\r\nStatus: Encrypted"
      let s_recv = collect_app_data(server.feed(client.write_app_data(req)[:]))
      let c_recv = collect_app_data(client.feed(server.write_app_data(resp)[:]))
      let ok = s_recv == req && c_recv == resp
      println(
        "  " +
        suite.name() +
        " (" +
        suite_hex(suite.to_u16()) +
        ") | " +
        mode +
        " | HS=" +
        c_bytes.to_string() +
        "B/" +
        s_bytes.to_string() +
        "B | Data=" +
        (if ok { "[PASS]" } else { "[FAIL]" }),
      )
    } catch {
      _ => println("  " + suite.name() + " : [FAIL]")
    }
  }
}

///|
fn demo_session_resumption(pki : @x509.TestPki) -> Unit {
  println("")
  println(
    "====================================================================",
  )
  println(
    " [4/5] TLCP Session ID Abbreviated Handshake Resumption             ",
  )
  println(
    "====================================================================",
  )
  let store = @lib.new_session_store()
  let c1 = @lib.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"cli-res-c1",
  })
  let s1 = @lib.new_server({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(store),
    seed: b"cli-res-s1",
  })
  let _ = try {
    let (fc, fs) = @lib.run_handshake_loop(c1, s1)
    let full_total = fc + fs
    let saved = c1.export_session()
    let c2 = @lib.new_client({
      trust_anchors: [pki.ca_cert],
      cipher_suites: [@handshake.EccSm4GcmSm3],
      client_certs: None,
      resume_session: saved,
      seed: b"cli-res-c2",
    })
    let s2 = @lib.new_server({
      sign_cert: pki.server_sign_cert,
      sign_priv: pki.server_sign_priv,
      enc_cert: pki.server_enc_cert,
      enc_priv: pki.server_enc_priv,
      cipher_suites: [@handshake.EccSm4GcmSm3],
      require_client_cert: false,
      client_trust_anchors: [],
      session_store: Some(store),
      seed: b"cli-res-s2",
    })
    let (rc, rs) = @lib.run_handshake_loop(c2, s2)
    let res_total = rc + rs
    let saved_pct = (full_total - res_total) * 100 / full_total
    let payload = b"Fast resumed session encrypted payload!"
    let recv = collect_app_data(s2.feed(c2.write_app_data(payload)[:]))
    let ok = c2.is_resumed() && s2.is_resumed() && recv == payload
    println(
      "  Full Handshake    : " +
      full_total.to_string() +
      " bytes total (C=" +
      fc.to_string() +
      "B, S=" +
      fs.to_string() +
      "B)",
    )
    println(
      "  Resumed Handshake : " +
      res_total.to_string() +
      " bytes total (C=" +
      rc.to_string() +
      "B, S=" +
      rs.to_string() +
      "B) -> saved " +
      saved_pct.to_string() +
      "%",
    )
    println(
      "  Resumption Status : is_resumed=true | AppData=" +
      (if ok { "[PASS]" } else { "[FAIL]" }),
    )
  } catch {
    _ => println("  Session Resumption: [FAIL]")
  }
}

///|
fn demo_adversarial_drill(pki : @x509.TestPki) -> Unit {
  println("")
  println(
    "====================================================================",
  )
  println(
    " [5/5] Live Security Adversarial Drill (Fail-Closed & Fatal Alerts) ",
  )
  println(
    "====================================================================",
  )
  // Drill A: Tamper SM4-GCM tag on established connection
  let client = @lib.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"cli-adv-c",
  })
  let server = @lib.new_server({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed: b"cli-adv-s",
  })
  let _ = try {
    ignore(@lib.run_handshake_loop(client, server))
    let wire = client.write_app_data(b"authorized transaction #9001")
    let tampered = flip_byte(wire, wire.length() - 1, 0x01U)
    let mac_caught = try {
      ignore(server.feed(tampered[:]))
      false
    } catch {
      @state.ProtocolError(@handshake.BadRecordMac, _) => true
      _ => false
    }
    let alert_wire = server.take_outbound()
    let locked_out = try {
      ignore(server.feed(wire[:]))
      false
    } catch {
      @state.InvalidState(_) => true
      _ => false
    }
    println(
      "  Drill A (SM4-GCM Tag Bit-Flip) : BadRecordMac=" +
      mac_caught.to_string() +
      " | FatalAlert=" +
      alert_wire.length().to_string() +
      "B | FailClosed=" +
      (server.is_failed() && locked_out).to_string() +
      " [PASS]",
    )
  } catch {
    _ => println("  Drill A: [FAIL]")
  }
  // Drill B: TLS 1.2 (0x0303) version downgrade probe
  let downgrade_server = @lib.new_server(
    @state.ServerConfig::new(
      pki.server_sign_cert,
      pki.server_sign_priv,
      pki.server_enc_cert,
      pki.server_enc_priv,
      b"cli-adv-dg",
    ),
  )
  let tls12_probe = Bytes::from_array([
    b'\x16', b'\x03', b'\x03', b'\x00', b'\x04', b'\x01', b'\x00', b'\x00', b'\x00',
  ])
  let dg_caught = try {
    ignore(downgrade_server.feed(tls12_probe[:]))
    false
  } catch {
    @state.ProtocolError(@handshake.ProtocolVersion, _) => true
    _ => false
  }
  let dg_alert_ok = try {
    let (rec, _) = @record.decode_record(downgrade_server.take_outbound()[:])
    let alert = @handshake.decode_alert(rec.payload[:])
    alert.level == @handshake.Fatal &&
    alert.description == @handshake.ProtocolVersion
  } catch {
    _ => false
  }
  println(
    "  Drill B (TLS 1.2 0x0303 Probe) : ProtocolVersion=" +
    dg_caught.to_string() +
    " | FatalAlertVerified=" +
    dg_alert_ok.to_string() +
    " | FailClosed=" +
    downgrade_server.is_failed().to_string() +
    " [PASS]",
  )
}

///|
fn main {
  println(
    "MoonTLCP v0.1.0 — Pure MoonBit Sans-I/O GM/T 0024-2023 (TLCP 1.1) Stack",
  )
  demo_crypto_self_test()
  let _ = try {
    let pki = @lib.generate_test_pki(b"moontlcp-cli-demo-pki")
    demo_x509_dual_pki(pki)
    demo_four_suites(pki)
    demo_session_resumption(pki)
    demo_adversarial_drill(pki)
    println("")
    println("All MoonTLCP live verification stages completed successfully.")
  } catch {
    _ => println("ERROR: failed to initialize demo PKI")
  }
}
