///|
/// Automated native OS TCP loopback tests (`127.0.0.1`) for the concurrent
/// MoonBit Async TLCP 1.1 reverse proxy.

///|
fn flip_wire_byte(data : Bytes, idx : Int32, mask : UInt32) -> Bytes {
  let out = FixedArray::make(data.length(), b'\x00')
  for i in 0..<data.length() {
    out[i] = data[i]
  }
  out[idx] = (out[idx].to_uint() ^ mask).to_byte()
  Bytes::from_array(out)
}

///|
test "PEM dual-certificate loading succeeds and blocks swapped [enc, sign] chains" {
  let pem_pki = @tlcp_async_proxy.export_test_pki_pem(b"proxy-pem-unit-test")
  let verified = @tlcp_async_proxy.load_dual_certs_from_pem(
    pem_pki.server_dual_pem,
    pem_pki.ca_pem,
  )
  assert_true(verified.sign_cert.subject_cn.length() > 0)
  assert_true(verified.enc_cert.subject_cn.length() > 0)
  assert_eq(verified.trust_anchors.length(), 1)
  // Swapping [enc, sign] in PEM order must be rejected by strict GM/T 0024 KeyUsage checks.
  let swapped_pem = verified.enc_cert.to_pem() +
    "\n" +
    verified.sign_cert.to_pem()
  let swapped_rejected = try {
    ignore(
      @tlcp_async_proxy.load_dual_certs_from_pem(swapped_pem, pem_pki.ca_pem),
    )
    false
  } catch {
    @tlcp_async_proxy.ConfigError(_) => true
    _ => false
  }
  assert_true(swapped_rejected)
}

///|
async test "concurrent ECC_SM4_GCM_SM3 reverse proxy forwarding and Session ID resumption" {
  let pem_pki = @tlcp_async_proxy.export_test_pki_pem(
    b"proxy-ecc-gcm-concurrent",
  )
  let verified_ca = @tlcp_async_proxy.load_dual_certs_from_pem(
    pem_pki.server_dual_pem,
    pem_pki.ca_pem,
  )
  let session_store = @moontlcp.new_session_store()
  let backend_stats = @tlcp_async_proxy.BackendStats::new()
  let proxy_stats = @tlcp_async_proxy.ProxyStats::new()
  let full_results : Array[@tlcp_async_proxy.TlcpHttpResult] = []
  let resumed_results : Array[@tlcp_async_proxy.TlcpHttpResult] = []
  @async.with_task_group(root => {
    let backend_server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let backend_addr = backend_server.addr
    let proxy_server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let proxy_addr = proxy_server.addr
    root.spawn_bg(no_wait=true, () => {
      @tlcp_async_proxy.serve_plaintext_http_backend(
        backend_server, backend_stats,
      )
    })
    root.spawn_bg(no_wait=true, () => {
      @tlcp_async_proxy.serve_tlcp_reverse_proxy(
        proxy_server,
        {
          server_dual_pem: pem_pki.server_dual_pem,
          ca_pem: pem_pki.ca_pem,
          server_sign_priv: pem_pki.server_sign_priv,
          server_enc_priv: pem_pki.server_enc_priv,
          cipher_suites: [@handshake.EccSm4GcmSm3],
          require_client_cert: false,
          session_store: Some(session_store),
          upstream_addr: backend_addr,
          base_seed: b"proxy-ecc-server-seed",
          max_connections: 16,
        },
        proxy_stats,
      )
    })
    // Phase 1: 4 concurrent clients executing full ECC_SM4_GCM_SM3 handshakes over real TCP
    let phase1 = @async.with_task_group(cg => {
      let tasks : Array[@async.Task[@tlcp_async_proxy.TlcpHttpResult]] = []
      for i in 0..<4 {
        let idx = i
        tasks.push(
          cg.spawn(() => {
            let req = @tlcp_async_proxy.build_http_request(
              "POST",
              "/gm/v1/full/" + idx.to_string(),
              "ecc-gcm-payload-" + idx.to_string(),
            )
            @tlcp_async_proxy.send_tlcp_http_request(
              proxy_addr,
              {
                trust_anchors: verified_ca.trust_anchors,
                cipher_suites: [@handshake.EccSm4GcmSm3],
                client_certs: None,
                resume_session: None,
                seed: @moontlcp.sm3_hash(
                  @utf8.encode("ecc-full-client-" + idx.to_string()),
                ),
              },
              req,
            )
          }),
        )
      }
      let out : Array[@tlcp_async_proxy.TlcpHttpResult] = []
      for t in tasks {
        out.push(t.wait())
      }
      out
    })
    for r in phase1 {
      full_results.push(r)
    }
    // Phase 2: 4 concurrent clients resuming cached sessions from proxy SessionStore
    let phase2 = @async.with_task_group(cg => {
      let tasks : Array[@async.Task[@tlcp_async_proxy.TlcpHttpResult]] = []
      for i in 0..<4 {
        let idx = i
        let saved = full_results[idx].exported_session
        tasks.push(
          cg.spawn(() => {
            let req = @tlcp_async_proxy.build_http_request(
              "GET",
              "/gm/v1/resumed/" + idx.to_string(),
              "",
            )
            @tlcp_async_proxy.send_tlcp_http_request(
              proxy_addr,
              {
                trust_anchors: verified_ca.trust_anchors,
                cipher_suites: [@handshake.EccSm4GcmSm3],
                client_certs: None,
                resume_session: saved,
                seed: @moontlcp.sm3_hash(
                  @utf8.encode("ecc-resumed-client-" + idx.to_string()),
                ),
              },
              req,
            )
          }),
        )
      }
      let out : Array[@tlcp_async_proxy.TlcpHttpResult] = []
      for t in tasks {
        out.push(t.wait())
      }
      out
    })
    for r in phase2 {
      resumed_results.push(r)
    }
  })
  assert_eq(full_results.length(), 4)
  assert_eq(resumed_results.length(), 4)
  for i in 0..<4 {
    let f = full_results[i]
    assert_eq(f.status_line, "HTTP/1.1 200 OK")
    assert_eq(f.negotiated_suite, @handshake.EccSm4GcmSm3)
    assert_eq(f.resumed, false)
    assert_true(f.exported_session is Some(_))
    assert_true(f.response_text.contains("X-TLCP-Suite: ECC_SM4_GCM_SM3"))
    assert_true(f.response_text.contains("X-TLCP-Resumed: false"))
    assert_true(
      f.response_text.contains(
        "POST /gm/v1/full/" + i.to_string() + " HTTP/1.1",
      ),
    )
    let r = resumed_results[i]
    assert_eq(r.status_line, "HTTP/1.1 200 OK")
    assert_eq(r.negotiated_suite, @handshake.EccSm4GcmSm3)
    assert_eq(r.resumed, true)
    assert_true(r.response_text.contains("X-TLCP-Resumed: true"))
    assert_true(
      r.handshake_wire_in + r.handshake_wire_out <
      f.handshake_wire_in + f.handshake_wire_out,
    )
  }
  assert_eq(backend_stats.requests_handled, 8)
  assert_eq(proxy_stats.handshakes_ok, 8)
  assert_eq(proxy_stats.resumed_sessions, 4)
  assert_eq(proxy_stats.forwarded_requests, 8)
  assert_eq(proxy_stats.rejected_conns, 0)
}

///|
async test "concurrent ECDHE_SM4_CBC_SM3 mTLCP mutual-auth reverse proxy rejects unauthenticated clients" {
  let pem_pki = @tlcp_async_proxy.export_test_pki_pem(b"proxy-mtcp-ecdhe-cbc")
  let client_certs = @tlcp_async_proxy.load_dual_certs_from_pem(
    pem_pki.client_dual_pem,
    pem_pki.ca_pem,
  )
  let backend_stats = @tlcp_async_proxy.BackendStats::new()
  let proxy_stats = @tlcp_async_proxy.ProxyStats::new()
  let mut unauth_rejected = false
  let results : Array[@tlcp_async_proxy.TlcpHttpResult] = []
  @async.with_task_group(root => {
    let backend_server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let backend_addr = backend_server.addr
    let proxy_server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let proxy_addr = proxy_server.addr
    root.spawn_bg(no_wait=true, () => {
      @tlcp_async_proxy.serve_plaintext_http_backend(
        backend_server, backend_stats,
      )
    })
    root.spawn_bg(no_wait=true, () => {
      @tlcp_async_proxy.serve_tlcp_reverse_proxy(
        proxy_server,
        {
          server_dual_pem: pem_pki.server_dual_pem,
          ca_pem: pem_pki.ca_pem,
          server_sign_priv: pem_pki.server_sign_priv,
          server_enc_priv: pem_pki.server_enc_priv,
          cipher_suites: [@handshake.EcdheSm4CbcSm3],
          require_client_cert: true,
          session_store: None,
          upstream_addr: backend_addr,
          base_seed: b"proxy-mtcp-server-seed",
          max_connections: 16,
        },
        proxy_stats,
      )
    })
    // 4 concurrent authenticated mTLCP clients
    let ok_batch = @async.with_task_group(cg => {
      let tasks : Array[@async.Task[@tlcp_async_proxy.TlcpHttpResult]] = []
      for i in 0..<4 {
        let idx = i
        tasks.push(
          cg.spawn(() => {
            let req = @tlcp_async_proxy.build_http_request(
              "POST",
              "/gm/v1/settlement/" + idx.to_string(),
              "mtcp-order-" + idx.to_string(),
            )
            @tlcp_async_proxy.send_tlcp_http_request(
              proxy_addr,
              {
                trust_anchors: client_certs.trust_anchors,
                cipher_suites: [@handshake.EcdheSm4CbcSm3],
                client_certs: Some(
                  (
                    client_certs.sign_cert,
                    pem_pki.client_sign_priv,
                    client_certs.enc_cert,
                    pem_pki.client_enc_priv,
                  ),
                ),
                resume_session: None,
                seed: @moontlcp.sm3_hash(
                  @utf8.encode("mtcp-client-" + idx.to_string()),
                ),
              },
              req,
            )
          }),
        )
      }
      let out : Array[@tlcp_async_proxy.TlcpHttpResult] = []
      for t in tasks {
        out.push(t.wait())
      }
      out
    })
    for r in ok_batch {
      results.push(r)
    }
    // 1 unauthenticated client (missing dual client certs) must fail mTLCP handshake
    unauth_rejected = try {
      ignore(
        @tlcp_async_proxy.send_tlcp_http_request(
          proxy_addr,
          {
            trust_anchors: client_certs.trust_anchors,
            cipher_suites: [@handshake.EcdheSm4CbcSm3],
            client_certs: None,
            resume_session: None,
            seed: b"mtcp-unauth-client",
          },
          @tlcp_async_proxy.build_http_request("GET", "/gm/v1/forbidden", ""),
        ),
      )
      false
    } catch {
      _ => true
    }
    @async.sleep(20)
  })
  assert_eq(results.length(), 4)
  for r in results {
    assert_eq(r.status_line, "HTTP/1.1 200 OK")
    assert_eq(r.negotiated_suite, @handshake.EcdheSm4CbcSm3)
    assert_true(r.response_text.contains("X-TLCP-Suite: ECDHE_SM4_CBC_SM3"))
    assert_true(
      r.response_text.contains(
        "X-TLCP-Client-CN: " + client_certs.sign_cert.subject_cn,
      ),
    )
  }
  assert_true(unauth_rejected)
  assert_eq(backend_stats.requests_handled, 4)
  assert_eq(proxy_stats.handshakes_ok, 4)
  assert_true(proxy_stats.rejected_conns >= 1)
}

///|
async test "tampered GCM ciphertext and TLS 1.2 downgrade trigger fail-closed disconnect over real TCP" {
  let pem_pki = @tlcp_async_proxy.export_test_pki_pem(b"proxy-tamper-drill")
  let verified = @tlcp_async_proxy.load_dual_certs_from_pem(
    pem_pki.server_dual_pem,
    pem_pki.ca_pem,
  )
  let backend_stats = @tlcp_async_proxy.BackendStats::new()
  let proxy_stats = @tlcp_async_proxy.ProxyStats::new()
  let mut tamper_alert_received = false
  let mut downgrade_alert_name = ""
  @async.with_task_group(root => {
    let backend_server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let backend_addr = backend_server.addr
    let proxy_server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let proxy_addr = proxy_server.addr
    root.spawn_bg(no_wait=true, () => {
      @tlcp_async_proxy.serve_plaintext_http_backend(
        backend_server, backend_stats,
      )
    })
    root.spawn_bg(no_wait=true, () => {
      @tlcp_async_proxy.serve_tlcp_reverse_proxy(
        proxy_server,
        {
          server_dual_pem: pem_pki.server_dual_pem,
          ca_pem: pem_pki.ca_pem,
          server_sign_priv: pem_pki.server_sign_priv,
          server_enc_priv: pem_pki.server_enc_priv,
          cipher_suites: [@handshake.EccSm4GcmSm3],
          require_client_cert: false,
          session_store: None,
          upstream_addr: backend_addr,
          base_seed: b"proxy-tamper-server-seed",
          max_connections: 16,
        },
        proxy_stats,
      )
    })
    // Drill 1: Complete valid TLCP handshake, flip 1 bit in GCM tag, send over raw TCP
    let client_stream = @tlcp_async_proxy.AsyncTlcpClientStream::connect(
      proxy_addr,
      {
        trust_anchors: verified.trust_anchors,
        cipher_suites: [@handshake.EccSm4GcmSm3],
        client_certs: None,
        resume_session: None,
        seed: b"tamper-client-seed",
      },
    )
    let valid_wire = client_stream.seal_record_bytes(
      @tlcp_async_proxy.build_http_request(
        "POST", "/gm/v1/transfer", "amount=999999",
      ),
    )
    let tampered_wire = flip_wire_byte(
      valid_wire,
      valid_wire.length() - 1,
      0x01U,
    )
    client_stream.raw_socket().write(tampered_wire)
    // Expect the proxy to respond with BadRecordMac Fatal Alert and close fail-closed
    tamper_alert_received = try {
      match client_stream.read_app_data() {
        None => true
        Some(_) => false
      }
    } catch {
      @tlcp_async_proxy.ProtocolRejected(msg) => msg.contains("BadRecordMac")
      _ => false
    }
    client_stream.close_socket_now()
    // Drill 2: Send raw TLS 1.2 (0x0303) ClientHello probe -> expect plaintext Fatal Alert ProtocolVersion
    let raw_probe_sock = @socket.Tcp::connect(proxy_addr)
    defer raw_probe_sock.close()
    let tls12_probe = Bytes::from_array([
      b'\x16', b'\x03', b'\x03', b'\x00', b'\x04', b'\x01', b'\x00', b'\x00', b'\x00',
    ])
    raw_probe_sock.write(tls12_probe)
    match raw_probe_sock.read_some() {
      Some(alert_wire) => {
        let rec = @moontlcp.inspect_record(alert_wire[:])
        assert_eq(rec.content_type_name, "Alert")
        assert_eq(rec.is_tlcp_1_1, true)
        let (lvl, desc, name) = @moontlcp.inspect_alert(
          alert_wire[rec.payload_offset:rec.payload_offset + rec.payload_len],
        )
        assert_eq(lvl, b'\x02')
        assert_eq(desc, b'\x46')
        downgrade_alert_name = name
      }
      None => ()
    }
    @async.sleep(20)
  })
  assert_true(tamper_alert_received)
  assert_eq(downgrade_alert_name, "ProtocolVersion")
  // Neither tampered request nor TLS 1.2 probe may ever reach plaintext backend!
  assert_eq(backend_stats.requests_handled, 0)
  assert_eq(proxy_stats.forwarded_requests, 0)
  assert_true(proxy_stats.rejected_conns >= 2)
}

///|
async test "large >16KB encrypted HTTP payload auto-fragments across multiple TLCP records over TCP" {
  let pem_pki = @tlcp_async_proxy.export_test_pki_pem(b"proxy-large-payload")
  let client_certs = @tlcp_async_proxy.load_dual_certs_from_pem(
    pem_pki.client_dual_pem,
    pem_pki.ca_pem,
  )
  let backend_stats = @tlcp_async_proxy.BackendStats::new()
  let proxy_stats = @tlcp_async_proxy.ProxyStats::new()
  let body_sb = StringBuilder()
  for _ in 0..<2048 {
    body_sb.write_string("SM4-GCM-16KB-CHUNK-")
  }
  let big_body = body_sb.to_string()
  assert_true(big_body.length() > 32768)
  let mut resp_text = ""
  @async.with_task_group(root => {
    let backend_server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let backend_addr = backend_server.addr
    let proxy_server = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let proxy_addr = proxy_server.addr
    root.spawn_bg(no_wait=true, () => {
      @tlcp_async_proxy.serve_plaintext_http_backend(
        backend_server, backend_stats,
      )
    })
    root.spawn_bg(no_wait=true, () => {
      @tlcp_async_proxy.serve_tlcp_reverse_proxy(
        proxy_server,
        {
          server_dual_pem: pem_pki.server_dual_pem,
          ca_pem: pem_pki.ca_pem,
          server_sign_priv: pem_pki.server_sign_priv,
          server_enc_priv: pem_pki.server_enc_priv,
          cipher_suites: [@handshake.EcdheSm4GcmSm3],
          require_client_cert: true,
          session_store: None,
          upstream_addr: backend_addr,
          base_seed: b"proxy-big-server-seed",
          max_connections: 8,
        },
        proxy_stats,
      )
    })
    let res = @tlcp_async_proxy.send_tlcp_http_request(
      proxy_addr,
      {
        trust_anchors: client_certs.trust_anchors,
        cipher_suites: [@handshake.EcdheSm4GcmSm3],
        client_certs: Some(
          (
            client_certs.sign_cert,
            pem_pki.client_sign_priv,
            client_certs.enc_cert,
            pem_pki.client_enc_priv,
          ),
        ),
        resume_session: None,
        seed: b"proxy-big-client-seed",
      },
      @tlcp_async_proxy.build_http_request(
        "POST", "/gm/v1/bulk-upload", big_body,
      ),
    )
    assert_eq(res.status_line, "HTTP/1.1 200 OK")
    assert_eq(res.negotiated_suite, @handshake.EcdheSm4GcmSm3)
    resp_text = res.response_text
  })
  assert_true(resp_text.contains("Body-Len: " + big_body.length().to_string()))
  assert_eq(backend_stats.requests_handled, 1)
  assert_eq(proxy_stats.forwarded_requests, 1)
}
