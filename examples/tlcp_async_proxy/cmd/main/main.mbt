///|
/// Native MoonBit Concurrent Async TLCP 1.1 Reverse Proxy Live Demo CLI.
///
/// Run on Windows (inside MSVC Developer Command Prompt / vcvars64):
///   `moon run --target native cmd/main`
/// Run on Linux / macOS:
///   `moon run --target native cmd/main`

///|
fn flip_last_byte(data : Bytes) -> Bytes {
  let out = FixedArray::make(data.length(), b'\x00')
  for i in 0..<data.length() {
    out[i] = data[i]
  }
  out[data.length() - 1] = (out[data.length() - 1].to_uint() ^ 0x01U).to_byte()
  Bytes::from_array(out)
}

///|
async fn main {
  println(
    "======================================================================",
  )
  println(
    " MoonTLCP v0.3.0 — Native Async TCP TLCP 1.1 Reverse Proxy Live Demo ",
  )
  println(
    " Runtime: moonbitlang/async/socket (TcpServer/Tcp + with_task_group) ",
  )
  println(
    "======================================================================",
  )
  // 1. Load & verify PEM dual certificates
  let pem_pki = @proxy.export_test_pki_pem(b"moontlcp-async-proxy-demo-pki")
  let verified_server = @proxy.load_dual_certs_from_pem(
    pem_pki.server_dual_pem,
    pem_pki.ca_pem,
  )
  let verified_client = @proxy.load_dual_certs_from_pem(
    pem_pki.client_dual_pem,
    pem_pki.ca_pem,
  )
  println(
    "[1/4] PEM Dual-Cert PKI Verified: server_sign=" +
    verified_server.sign_cert.subject_cn +
    " | server_enc=" +
    verified_server.enc_cert.subject_cn +
    " | client_sign=" +
    verified_client.sign_cert.subject_cn,
  )
  // 2. Concurrent ECC_SM4_GCM_SM3 reverse proxy + Session ID resumption
  let store = @moontlcp.new_session_store()
  let backend_stats = @proxy.BackendStats::new()
  let proxy_stats = @proxy.ProxyStats::new()
  @async.with_task_group(root => {
    let backend = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let backend_addr = backend.addr
    let proxy = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let proxy_addr = proxy.addr
    println(
      "[2/4] Reverse Proxy listening on " +
      proxy_addr.to_string() +
      " -> Plaintext HTTP Backend " +
      backend_addr.to_string(),
    )
    root.spawn_bg(no_wait=true, () => {
      @proxy.serve_plaintext_http_backend(backend, backend_stats)
    })
    root.spawn_bg(no_wait=true, () => {
      @proxy.serve_tlcp_reverse_proxy(
        proxy,
        {
          server_dual_pem: pem_pki.server_dual_pem,
          ca_pem: pem_pki.ca_pem,
          server_sign_priv: pem_pki.server_sign_priv,
          server_enc_priv: pem_pki.server_enc_priv,
          cipher_suites: [@handshake.EccSm4GcmSm3],
          require_client_cert: false,
          session_store: Some(store),
          upstream_addr: backend_addr,
          base_seed: b"demo-ecc-proxy",
          max_connections: 16,
        },
        proxy_stats,
      )
    })
    let first_wave = @async.with_task_group(cg => {
      let tasks : Array[@async.Task[@proxy.TlcpHttpResult]] = []
      for i in 0..<3 {
        let idx = i
        tasks.push(
          cg.spawn(() => {
            @proxy.send_tlcp_http_request(
              proxy_addr,
              {
                trust_anchors: verified_server.trust_anchors,
                cipher_suites: [@handshake.EccSm4GcmSm3],
                client_certs: None,
                resume_session: None,
                seed: @moontlcp.sm3_hash(
                  @utf8.encode("demo-ecc-full-" + idx.to_string()),
                ),
              },
              @proxy.build_http_request(
                "POST",
                "/api/v1/pay/" + idx.to_string(),
                "order=" + idx.to_string(),
              ),
            )
          }),
        )
      }
      let out : Array[@proxy.TlcpHttpResult] = []
      for t in tasks {
        out.push(t.wait())
      }
      out
    })
    let full_hs = first_wave[0].handshake_wire_in +
      first_wave[0].handshake_wire_out
    let resumed_res = @proxy.send_tlcp_http_request(
      proxy_addr,
      {
        trust_anchors: verified_server.trust_anchors,
        cipher_suites: [@handshake.EccSm4GcmSm3],
        client_certs: None,
        resume_session: first_wave[0].exported_session,
        seed: b"demo-ecc-resumed",
      },
      @proxy.build_http_request("GET", "/api/v1/balance", ""),
    )
    let res_hs = resumed_res.handshake_wire_in + resumed_res.handshake_wire_out
    println(
      "      ECC_SM4_GCM_SM3: 3 concurrent full (" +
      full_hs.to_string() +
      "B HS) + 1 Session-ID resumed (" +
      res_hs.to_string() +
      "B HS, resumed=" +
      resumed_res.resumed.to_string() +
      ") -> " +
      resumed_res.status_line,
    )
    // Live tamper drill on the same live proxy
    let tamper_client = @proxy.AsyncTlcpClientStream::connect(proxy_addr, {
      trust_anchors: verified_server.trust_anchors,
      cipher_suites: [@handshake.EccSm4GcmSm3],
      client_certs: None,
      resume_session: None,
      seed: b"demo-tamper-client",
    })
    let wire = tamper_client.seal_record_bytes(
      @proxy.build_http_request("POST", "/api/v1/forged", "tamper"),
    )
    tamper_client.raw_socket().write(flip_last_byte(wire))
    let tamper_blocked = try {
      ignore(tamper_client.read_app_data())
      false
    } catch {
      _ => true
    }
    tamper_client.close_socket_now()
    @async.sleep(10)
    println(
      "[3/4] Ciphertext GCM Tag Tamper Drill: blocked=" +
      tamper_blocked.to_string() +
      " | proxy_rejected=" +
      proxy_stats.rejected_conns.to_string() +
      " | backend_forwarded=" +
      backend_stats.requests_handled.to_string(),
    )
  })
  // 3. Concurrent ECDHE_SM4_CBC_SM3 mTLCP mutual-auth reverse proxy
  let mtcp_backend_stats = @proxy.BackendStats::new()
  let mtcp_proxy_stats = @proxy.ProxyStats::new()
  @async.with_task_group(root => {
    let backend = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let backend_addr = backend.addr
    let proxy = @socket.TcpServer(@socket.Addr::parse("127.0.0.1:0"))
    let proxy_addr = proxy.addr
    root.spawn_bg(no_wait=true, () => {
      @proxy.serve_plaintext_http_backend(backend, mtcp_backend_stats)
    })
    root.spawn_bg(no_wait=true, () => {
      @proxy.serve_tlcp_reverse_proxy(
        proxy,
        {
          server_dual_pem: pem_pki.server_dual_pem,
          ca_pem: pem_pki.ca_pem,
          server_sign_priv: pem_pki.server_sign_priv,
          server_enc_priv: pem_pki.server_enc_priv,
          cipher_suites: [@handshake.EcdheSm4CbcSm3],
          require_client_cert: true,
          session_store: None,
          upstream_addr: backend_addr,
          base_seed: b"demo-mtcp-proxy",
          max_connections: 16,
        },
        mtcp_proxy_stats,
      )
    })
    let mtcp_wave = @async.with_task_group(cg => {
      let tasks : Array[@async.Task[@proxy.TlcpHttpResult]] = []
      for i in 0..<3 {
        let idx = i
        tasks.push(
          cg.spawn(() => {
            @proxy.send_tlcp_http_request(
              proxy_addr,
              {
                trust_anchors: verified_client.trust_anchors,
                cipher_suites: [@handshake.EcdheSm4CbcSm3],
                client_certs: Some(
                  (
                    verified_client.sign_cert,
                    pem_pki.client_sign_priv,
                    verified_client.enc_cert,
                    pem_pki.client_enc_priv,
                  ),
                ),
                resume_session: None,
                seed: @moontlcp.sm3_hash(
                  @utf8.encode("demo-mtcp-client-" + idx.to_string()),
                ),
              },
              @proxy.build_http_request(
                "POST",
                "/api/v1/mtcp/" + idx.to_string(),
                "settlement=" + idx.to_string(),
              ),
            )
          }),
        )
      }
      let out : Array[@proxy.TlcpHttpResult] = []
      for t in tasks {
        out.push(t.wait())
      }
      out
    })
    println(
      "[4/4] mTLCP ECDHE_SM4_CBC_SM3: " +
      mtcp_wave.length().to_string() +
      " concurrent mutual-auth clients -> " +
      mtcp_wave[0].status_line +
      " (forwarded=" +
      mtcp_proxy_stats.forwarded_requests.to_string() +
      ")",
    )
  })
  println(
    "All native OS loopback TCP TLCP 1.1 reverse proxy scenarios completed cleanly (graceful shutdown).",
  )
}
