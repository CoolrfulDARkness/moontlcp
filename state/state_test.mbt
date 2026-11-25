///|
fn make_payload(len : Int32, seed : Int32) -> Bytes {
  let out = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = ((i * 37 + seed * 19 + 11) & 0xFF).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn concat_events_data(events : Array[@state.Event]) -> Bytes {
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
fn has_handshake_complete(events : Array[@state.Event]) -> Bool {
  for i = 0; i < events.length(); i = i + 1 {
    if events[i] == @state.HandshakeComplete {
      return true
    }
  }
  false
}

///|
fn run_handshake(
  client : @state.ClientConn,
  server : @state.ServerConn,
) -> (Bool, Bool) raise @state.StateError {
  let mut c_done = false
  let mut s_done = false
  let mut to_server = client.start_handshake()
  for _round = 0; _round < 8; _round = _round + 1 {
    if to_server.length() > 0 {
      let s_ev = server.feed(to_server[:])
      if has_handshake_complete(s_ev) {
        s_done = true
      }
      to_server = b""
    }
    let to_client = server.take_outbound()
    if to_client.length() > 0 {
      let c_ev = client.feed(to_client[:])
      if has_handshake_complete(c_ev) {
        c_done = true
      }
    }
    to_server = client.take_outbound()
    if to_server.length() == 0 &&
      client.is_established() &&
      server.is_established() {
      break
    }
  }
  (c_done, s_done)
}

///|
test "end-to-end TLCP 1.1 handshake and bidirectional data across all 4 national cipher suites" {
  let pki = @x509.generate_test_pki(b"moontlcp-e2e-4-suites")
  let suites : Array[@handshake.CipherSuite] = [
    @handshake.EccSm4CbcSm3,
    @handshake.EccSm4GcmSm3,
    @handshake.EcdheSm4CbcSm3,
    @handshake.EcdheSm4GcmSm3,
  ]
  for idx = 0; idx < suites.length(); idx = idx + 1 {
    let suite = suites[idx]
    let c_cfg = @state.ClientConfig::{
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
      seed: make_payload(32, 10 + idx),
    }
    let s_cfg = @state.ServerConfig::{
      sign_cert: pki.server_sign_cert,
      sign_priv: pki.server_sign_priv,
      enc_cert: pki.server_enc_cert,
      enc_priv: pki.server_enc_priv,
      cipher_suites: [suite],
      require_client_cert: suite.is_ecdhe(),
      client_trust_anchors: [pki.ca_cert],
      session_store: None,
      seed: make_payload(32, 20 + idx),
    }
    let client = @state.ClientConn::new(c_cfg)
    let server = @state.ServerConn::new(s_cfg)
    let (c_done, s_done) = run_handshake(client, server)
    assert_true(c_done)
    assert_true(s_done)
    assert_true(client.is_established())
    assert_true(server.is_established())
    assert_true(!client.is_failed())
    assert_true(!server.is_failed())
    assert_true(!client.is_resumed())
    assert_true(!server.is_resumed())
    assert_eq(client.negotiated_suite(), Some(suite))
    assert_eq(server.negotiated_suite(), Some(suite))
    assert_eq(client.session_id(), server.session_id())
    assert_eq(client.session_id().length(), 32)
    assert_true(client.peer_certs() is Some(_))
    assert_eq(server.peer_certs() is Some(_), suite.is_ecdhe())
    // Bidirectional encrypted ApplicationData
    let c_msg = b"GET /tlcp/gm-status HTTP/1.1\r\nHost: moontlcp.cn\r\n\r\n"
    let s_msg = b"HTTP/1.1 200 OK\r\nX-Protocol: TLCP-1.1\r\n\r\nOK"
    let c_wire = client.write_app_data(c_msg)
    let s_ev = server.feed(c_wire[:])
    assert_eq(concat_events_data(s_ev), c_msg)
    let s_wire = server.write_app_data(s_msg)
    let c_ev = client.feed(s_wire[:])
    assert_eq(concat_events_data(c_ev), s_msg)
  }
}

///|
test "mutual TLCP (mTLCP) on static ECC suite verifies both dual-certificate bundles" {
  let pki = @x509.generate_test_pki(b"moontlcp-ecc-mtls")
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
    seed: b"client-mtls-seed",
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
    seed: b"server-mtls-seed",
  })
  let (c_done, s_done) = run_handshake(client, server)
  assert_true(c_done)
  assert_true(s_done)
  assert_true(client.peer_certs() is Some(_))
  assert_true(server.peer_certs() is Some(_))
  match server.peer_certs() {
    Some(bundle) => {
      assert_eq(bundle.sign_cert.raw_der, pki.client_sign_cert.raw_der)
      assert_eq(bundle.enc_cert.raw_der, pki.client_enc_cert.raw_der)
    }
    None => assert_true(false)
  }
}

///|
test "large >40KB multi-fragment transfer over CBC and GCM" {
  let pki = @x509.generate_test_pki(b"moontlcp-large-transfer")
  for suite in [@handshake.EccSm4CbcSm3, @handshake.EccSm4GcmSm3] {
    let client = @state.ClientConn::new({
      trust_anchors: [pki.ca_cert],
      cipher_suites: [suite],
      client_certs: None,
      resume_session: None,
      seed: b"large-client",
    })
    let server = @state.ServerConn::new({
      sign_cert: pki.server_sign_cert,
      sign_priv: pki.server_sign_priv,
      enc_cert: pki.server_enc_cert,
      enc_priv: pki.server_enc_priv,
      cipher_suites: [suite],
      require_client_cert: false,
      client_trust_anchors: [],
      session_store: None,
      seed: b"large-server",
    })
    ignore(run_handshake(client, server))
    let big_up = make_payload(42000, 1)
    let big_down = make_payload(35000, 2)
    let up_wire = client.write_app_data(big_up)
    let s_ev = server.feed(up_wire[:])
    // 42000 bytes splits into 3 records (16384 + 16384 + 9232)
    assert_eq(s_ev.length(), 3)
    assert_eq(concat_events_data(s_ev), big_up)
    let down_wire = server.write_app_data(big_down)
    let c_ev = client.feed(down_wire[:])
    assert_eq(c_ev.length(), 3)
    assert_eq(concat_events_data(c_ev), big_down)
  }
}

///|
test "1-byte trickle TCP delivery stress test across full ECDHE handshake and encrypted messaging" {
  let pki = @x509.generate_test_pki(b"moontlcp-1byte-trickle")
  let client = @state.ClientConn::new({
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
    seed: b"trickle-client",
  })
  let server = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EcdheSm4CbcSm3],
    require_client_cert: true,
    client_trust_anchors: [pki.ca_cert],
    session_store: None,
    seed: b"trickle-server",
  })
  fn feed_server_trickle(
    s : @state.ServerConn,
    wire : Bytes,
  ) -> Array[@state.Event] raise @state.StateError {
    let all : Array[@state.Event] = []
    for i = 0; i < wire.length(); i = i + 1 {
      let evs = s.feed(wire[i:i + 1])
      for j = 0; j < evs.length(); j = j + 1 {
        all.push(evs[j])
      }
    }
    all
  }
  fn feed_client_trickle(
    c : @state.ClientConn,
    wire : Bytes,
  ) -> Array[@state.Event] raise @state.StateError {
    let all : Array[@state.Event] = []
    for i = 0; i < wire.length(); i = i + 1 {
      let evs = c.feed(wire[i:i + 1])
      for j = 0; j < evs.length(); j = j + 1 {
        all.push(evs[j])
      }
    }
    all
  }
  let ch = client.start_handshake()
  ignore(feed_server_trickle(server, ch))
  let s_flight = server.take_outbound()
  ignore(feed_client_trickle(client, s_flight))
  let c_flight = client.take_outbound()
  let s_ev = feed_server_trickle(server, c_flight)
  assert_true(has_handshake_complete(s_ev))
  let s_fin = server.take_outbound()
  let c_ev = feed_client_trickle(client, s_fin)
  assert_true(has_handshake_complete(c_ev))
  assert_true(client.is_established())
  assert_true(server.is_established())
  let msg = b"1-byte trickle verified over ECDHE_SM4_CBC_SM3!"
  let app_wire = client.write_app_data(msg)
  let recv_ev = feed_server_trickle(server, app_wire)
  assert_eq(concat_events_data(recv_ev), msg)
}

///|
test "Session ID abbreviated handshake resumption and graceful CloseNotify" {
  let pki = @x509.generate_test_pki(b"moontlcp-session-resumption")
  let store = @state.SessionStore::new()
  // 1. Full handshake populates SessionStore
  let c1 = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: None,
    seed: b"res-client-1",
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
    seed: b"res-server-1",
  })
  ignore(run_handshake(c1, s1))
  assert_true(!c1.is_resumed())
  assert_true(!s1.is_resumed())
  assert_eq(store.len(), 1)
  let saved = match c1.export_session() {
    Some(sess) => sess
    None => abort("expected exported session")
  }
  assert_eq(saved.session_id, c1.session_id())
  assert_eq(saved.cipher_suite, @handshake.EccSm4GcmSm3)
  assert_eq(saved.master_secret.length(), 48)
  // 2. Abbreviated handshake reuses session ID
  let c2 = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: Some(saved),
    seed: b"res-client-2",
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
    seed: b"res-server-2",
  })
  let (c2_done, s2_done) = run_handshake(c2, s2)
  assert_true(c2_done)
  assert_true(s2_done)
  assert_true(c2.is_resumed())
  assert_true(s2.is_resumed())
  assert_eq(c2.session_id(), saved.session_id)
  // Exchange encrypted data over resumed session
  let ping = b"resumed ping"
  let pong = b"resumed pong"
  let ev_s = s2.feed(c2.write_app_data(ping)[:])
  assert_eq(concat_events_data(ev_s), ping)
  let ev_c = c2.feed(s2.write_app_data(pong)[:])
  assert_eq(concat_events_data(ev_c), pong)
  // Graceful CloseNotify in both directions
  let c_close = c2.close_notify()
  let s_close_ev = s2.feed(c_close[:])
  assert_eq(s_close_ev, [@state.PeerClosed])
  let s_close = s2.close_notify()
  let c_close_ev = c2.feed(s_close[:])
  assert_eq(c_close_ev, [@state.PeerClosed])
  // 3. Fallback to full handshake when session is evicted from store
  store.remove(saved.session_id)
  assert_eq(store.len(), 0)
  let c3 = @state.ClientConn::new({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [@handshake.EccSm4GcmSm3],
    client_certs: None,
    resume_session: Some(saved),
    seed: b"res-client-3",
  })
  let s3 = @state.ServerConn::new({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [@handshake.EccSm4GcmSm3],
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: Some(store),
    seed: b"res-server-3",
  })
  ignore(run_handshake(c3, s3))
  assert_true(!c3.is_resumed())
  assert_true(!s3.is_resumed())
  assert_true(c3.session_id() != saved.session_id)
}
