///|
/// Concurrent Native MoonBit TLCP 1.1 Reverse Proxy, Plaintext HTTP/1.1 Backend,
/// and Async TLCP HTTP Client running over real OS loopback TCP (`127.0.0.1`).

///|
pub(all) struct ProxyConfig {
  server_dual_pem : String
  ca_pem : String
  server_sign_priv : @sm2.PrivateKey
  server_enc_priv : @sm2.PrivateKey
  cipher_suites : Array[@handshake.CipherSuite]
  require_client_cert : Bool
  session_store : @state.SessionStore?
  upstream_addr : @socket.Addr
  base_seed : Bytes
  max_connections : Int32
}

///|
pub struct ProxyStats {
  mut total_accepted : Int32
  mut handshakes_ok : Int32
  mut resumed_sessions : Int32
  mut rejected_conns : Int32
  mut forwarded_requests : Int32
  mut total_upstream_bytes : Int32
  mut total_downstream_bytes : Int32
}

///|
pub fn ProxyStats::new() -> ProxyStats {
  {
    total_accepted: 0,
    handshakes_ok: 0,
    resumed_sessions: 0,
    rejected_conns: 0,
    forwarded_requests: 0,
    total_upstream_bytes: 0,
    total_downstream_bytes: 0,
  }
}

///|
pub struct BackendStats {
  mut requests_handled : Int32
}

///|
pub fn BackendStats::new() -> BackendStats {
  { requests_handled: 0, }
}

///|
pub(all) struct TlcpHttpResult {
  status_line : String
  response_text : String
  response_bytes : Bytes
  negotiated_suite : @handshake.CipherSuite
  resumed : Bool
  handshake_wire_in : Int32
  handshake_wire_out : Int32
  exported_session : @state.ResumedSession?
}

///|
fn find_crlf_crlf(buf : Array[Byte]) -> Int32? {
  if buf.length() < 4 {
    return None
  }
  for i in 0..<(buf.length() - 3) {
    if buf[i] == b'\r' &&
      buf[i + 1] == b'\n' &&
      buf[i + 2] == b'\r' &&
      buf[i + 3] == b'\n' {
      return Some(i + 4)
    }
  }
  None
}

///|
fn ascii_lower(c : Int32) -> Int32 {
  if c >= 65 && c <= 90 {
    c + 32
  } else {
    c
  }
}

///|
fn parse_decimal_int(s : String) -> Int32 {
  let mut acc = 0
  let mut started = false
  for i in 0..<s.length() {
    let c = s[i].to_int()
    if c == 32 || c == 9 {
      if started {
        break
      }
      continue
    }
    if c >= 48 && c <= 57 {
      started = true
      acc = acc * 10 + (c - 48)
    } else {
      break
    }
  }
  acc
}

///|
fn starts_with_ci(line : String, prefix_lower : String) -> Bool {
  if line.length() < prefix_lower.length() {
    return false
  }
  for i in 0..<prefix_lower.length() {
    if ascii_lower(line[i].to_int()) != prefix_lower[i].to_int() {
      return false
    }
  }
  true
}

///|
fn string_slice(s : String, start : Int32, end : Int32) -> String {
  let sb = StringBuilder()
  let mut i = start
  while i < end && i < s.length() {
    sb.write_char(s[i].to_int().unsafe_to_char())
    i += 1
  }
  sb.to_string()
}

///|
fn split_crlf_lines(text : String) -> Array[String] {
  let lines : Array[String] = []
  let mut start = 0
  let mut i = 0
  while i < text.length() {
    if i + 1 < text.length() &&
      text[i].to_int() == 13 &&
      text[i + 1].to_int() == 10 {
      lines.push(string_slice(text, start, i))
      i += 2
      start = i
    } else {
      i += 1
    }
  }
  if start < text.length() {
    lines.push(string_slice(text, start, text.length()))
  }
  lines
}

///|
fn parse_content_length(header_bytes : Bytes) -> Int32? {
  let text = @utf8.decode(header_bytes[:]) catch { _ => return None }
  let lines = split_crlf_lines(text)
  for line in lines {
    if starts_with_ci(line, "content-length:") {
      let val = string_slice(line, 15, line.length())
      return Some(parse_decimal_int(val))
    }
  }
  None
}

///|
fn extract_first_line(text : String) -> String {
  let lines = split_crlf_lines(text)
  if lines.is_empty() {
    ""
  } else {
    lines[0]
  }
}

///|
/// Injects `extra_headers` (each line ending in `\r\n`) right before the HTTP
/// header terminator `\r\n\r\n`.
fn inject_http_headers(raw_req : Bytes, extra_headers : String) -> Bytes {
  let arr : Array[Byte] = []
  append_bytes_to_buf(arr, raw_req)
  match find_crlf_crlf(arr) {
    None => raw_req
    Some(header_end) => {
      let insert_pos = header_end - 2
      let head = raw_req[0:insert_pos].to_owned()
      let extra = @utf8.encode(extra_headers)
      let tail = raw_req[insert_pos:raw_req.length()].to_owned()
      concat_bytes([head, extra, tail])
    }
  }
}

///|
async fn read_http_from_tlcp_server(stream : AsyncTlcpServerStream) -> Bytes? {
  let buf : Array[Byte] = []
  let mut header_end : Int32? = None
  let mut expected_total : Int32? = None
  for ;; {
    if header_end is None {
      match find_crlf_crlf(buf) {
        Some(end_idx) => {
          header_end = Some(end_idx)
          let hdr_bytes = Bytes::from_array(buf[:end_idx])
          let cl = match parse_content_length(hdr_bytes) {
            Some(n) => n
            None => 0
          }
          expected_total = Some(end_idx + cl)
        }
        None => ()
      }
    }
    if expected_total is Some(target) && buf.length() >= target {
      return Some(Bytes::from_array(buf[:target]))
    }
    match stream.read_app_data() {
      None =>
        if buf.is_empty() {
          return None
        } else {
          return Some(Bytes::from_array(buf[:]))
        }
      Some(chunk) => append_bytes_to_buf(buf, chunk)
    }
  }
}

///|
async fn read_http_from_tlcp_client(stream : AsyncTlcpClientStream) -> Bytes {
  let buf : Array[Byte] = []
  let mut header_end : Int32? = None
  let mut expected_total : Int32? = None
  for ;; {
    if header_end is None {
      match find_crlf_crlf(buf) {
        Some(end_idx) => {
          header_end = Some(end_idx)
          let hdr_bytes = Bytes::from_array(buf[:end_idx])
          match parse_content_length(hdr_bytes) {
            Some(n) => expected_total = Some(end_idx + n)
            None => ()
          }
        }
        None => ()
      }
    }
    if expected_total is Some(target) && buf.length() >= target {
      return Bytes::from_array(buf[:target])
    }
    match stream.read_app_data() {
      None => return Bytes::from_array(buf[:])
      Some(chunk) => append_bytes_to_buf(buf, chunk)
    }
  }
}

///|
async fn read_http_from_tcp(
  sock : @socket.Tcp,
  default_zero_body : Bool,
) -> Bytes? {
  let buf : Array[Byte] = []
  let mut header_end : Int32? = None
  let mut expected_total : Int32? = None
  for ;; {
    if header_end is None {
      match find_crlf_crlf(buf) {
        Some(end_idx) => {
          header_end = Some(end_idx)
          let hdr_bytes = Bytes::from_array(buf[:end_idx])
          match parse_content_length(hdr_bytes) {
            Some(n) => expected_total = Some(end_idx + n)
            None => if default_zero_body { expected_total = Some(end_idx) }
          }
        }
        None => ()
      }
    }
    if expected_total is Some(target) && buf.length() >= target {
      return Some(Bytes::from_array(buf[:target]))
    }
    match sock.read_some() {
      None =>
        if buf.is_empty() {
          return None
        } else {
          return Some(Bytes::from_array(buf[:]))
        }
      Some(chunk) => append_bytes_to_buf(buf, chunk)
    }
  }
}

///|
/// Runs a real OS TCP plaintext HTTP/1.1 upstream backend that inspects
/// forwarded `X-TLCP-*` proxy metadata headers and echoes summary details.
pub async fn serve_plaintext_http_backend(
  listener : @socket.TcpServer,
  stats : BackendStats,
) -> Unit {
  listener.run_forever(allow_failure=true, (sock, _peer_addr) => {
    match read_http_from_tcp(sock, true) {
      None => ()
      Some(raw_req) => {
        stats.requests_handled += 1
        let arr : Array[Byte] = []
        append_bytes_to_buf(arr, raw_req)
        let (hdr_text, body_len, body_sample) = match find_crlf_crlf(arr) {
          Some(end_idx) => {
            let h = @utf8.decode(raw_req[0:end_idx]) catch { _ => "" }
            let blen = raw_req.length() - end_idx
            let sample_len = if blen > 64 { 64 } else { blen }
            let sample = @utf8.decode(raw_req[end_idx:end_idx + sample_len]) catch {
              _ => "<binary>"
            }
            (h, blen, sample)
          }
          None => (@utf8.decode(raw_req[:]) catch { _ => "" }, 0, "")
        }
        let lines = split_crlf_lines(hdr_text)
        let req_line = if lines.is_empty() { "" } else { lines[0] }
        let body_sb = StringBuilder()
        body_sb.write_string("BACKEND_OK\n")
        body_sb.write_string("Request: " + req_line + "\n")
        for line in lines {
          if starts_with_ci(line, "x-tlcp-") {
            body_sb.write_string(line + "\n")
          }
        }
        body_sb.write_string("Body-Len: " + body_len.to_string() + "\n")
        if body_len > 0 {
          body_sb.write_string("Body-Prefix: " + body_sample + "\n")
        }
        let body_bytes = @utf8.encode(body_sb.to_string())
        let resp_hdr = "HTTP/1.1 200 OK\r\n" +
          "Content-Type: text/plain; charset=utf-8\r\n" +
          "X-Upstream-Backend: moontlcp-plaintext-http\r\n" +
          "Content-Length: " +
          body_bytes.length().to_string() +
          "\r\n" +
          "Connection: close\r\n\r\n"
        sock.write(concat_bytes([@utf8.encode(resp_hdr), body_bytes]))
      }
    }
  })
}

///|
async fn handle_proxy_client(
  client_sock : @socket.Tcp,
  verified : VerifiedDualCerts,
  config : ProxyConfig,
  stats : ProxyStats,
) -> Unit {
  stats.total_accepted += 1
  let conn_id = stats.total_accepted
  let conn_seed = @moontlcp.sm3_hash(
    concat_bytes([
      config.base_seed,
      @utf8.encode("-conn-" + conn_id.to_string()),
    ]),
  )
  let server_cfg : @state.ServerConfig = {
    sign_cert: verified.sign_cert,
    sign_priv: config.server_sign_priv,
    enc_cert: verified.enc_cert,
    enc_priv: config.server_enc_priv,
    cipher_suites: config.cipher_suites,
    require_client_cert: config.require_client_cert,
    client_trust_anchors: if config.require_client_cert {
      verified.trust_anchors
    } else {
      []
    },
    session_store: config.session_store,
    seed: conn_seed,
  }
  let tlcp = AsyncTlcpServerStream::accept(client_sock, server_cfg) catch {
    _ => {
      stats.rejected_conns += 1
      return
    }
  }
  stats.handshakes_ok += 1
  if tlcp.is_resumed() {
    stats.resumed_sessions += 1
  }
  let raw_req = match
    (read_http_from_tlcp_server(tlcp) catch {
      _ => {
        stats.rejected_conns += 1
        return
      }
    }) {
    None => {
      tlcp.close_notify()
      return
    }
    Some(req) => req
  }
  let suite_name = match tlcp.negotiated_suite() {
    Some(s) => s.name()
    None => "UNKNOWN"
  }
  let extra_sb = StringBuilder()
  extra_sb.write_string("X-TLCP-Suite: " + suite_name + "\r\n")
  extra_sb.write_string(
    "X-TLCP-Resumed: " + tlcp.is_resumed().to_string() + "\r\n",
  )
  extra_sb.write_string("X-TLCP-Conn-Id: " + conn_id.to_string() + "\r\n")
  match tlcp.peer_certs() {
    Some(bundle) =>
      extra_sb.write_string(
        "X-TLCP-Client-CN: " + bundle.sign_cert.subject_cn + "\r\n",
      )
    None => ()
  }
  let forwarded = inject_http_headers(raw_req, extra_sb.to_string())
  let upstream = @socket.Tcp::connect(config.upstream_addr)
  defer upstream.close()
  upstream.write(forwarded)
  stats.total_upstream_bytes += forwarded.length()
  let upstream_resp = match read_http_from_tcp(upstream, false) {
    Some(resp) => resp
    None =>
      @utf8.encode(
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
      )
  }
  tlcp.write_app_data(upstream_resp)
  stats.forwarded_requests += 1
  stats.total_downstream_bytes += upstream_resp.length()
  tlcp.close_notify()
}

///|
/// Runs the concurrent native MoonBit TLCP 1.1 reverse proxy on `listener`.
///
/// Uses `@async.with_task_group` + `@async.Semaphore` + `@socket.TcpServer::accept`
/// so each accepted TCP client runs concurrently with bounded concurrency:
/// 1. Validates and terminates TLCP 1.1 using PEM-loaded SM2 dual certificates
///    and optional `SessionStore` resumption / mTLCP client authentication;
/// 2. Decrypts the incoming HTTP/1.1 request and injects `X-TLCP-*` audit headers;
/// 3. Forwards the plaintext HTTP/1.1 request over OS TCP to `config.upstream_addr`;
/// 4. Encrypts the upstream HTTP/1.1 response back to the client and sends a
///    graceful TLCP `close_notify` alert.
pub async fn serve_tlcp_reverse_proxy(
  listener : @socket.TcpServer,
  config : ProxyConfig,
  stats : ProxyStats,
) -> Unit {
  defer listener.close()
  let verified = load_dual_certs_from_pem(config.server_dual_pem, config.ca_pem)
  let limit = @async.Semaphore(
    if config.max_connections > 0 {
      config.max_connections
    } else {
      16
    },
  )
  @async.with_task_group(group => {
    for ;; {
      limit.acquire()
      let (client_sock, _peer_addr) = listener.accept()
      group.spawn_bg(allow_failure=true, () => {
        defer client_sock.close()
        defer limit.release()
        handle_proxy_client(client_sock, verified, config, stats)
      })
    }
  })
}

///|
/// Performs a single end-to-end TLCP 1.1 HTTPS-style request against a TLCP
/// reverse proxy listening on `proxy_addr`.
pub async fn send_tlcp_http_request(
  proxy_addr : @socket.Addr,
  client_config : @state.ClientConfig,
  http_request : Bytes,
) -> TlcpHttpResult {
  let stream = AsyncTlcpClientStream::connect(proxy_addr, client_config)
  defer @async.protect_from_cancel(() => stream.close())
  let hs_in = stream.wire_in()
  let hs_out = stream.wire_out()
  let suite = match stream.negotiated_suite() {
    Some(s) => s
    None => raise HandshakeFailed("no cipher suite negotiated")
  }
  let resumed = stream.is_resumed()
  stream.write_app_data(http_request)
  let resp_bytes = read_http_from_tlcp_client(stream)
  let resp_text = @utf8.decode(resp_bytes[:]) catch {
    _ => raise HttpParseError("invalid UTF-8 HTTP response")
  }
  let exported = stream.export_session()
  {
    status_line: extract_first_line(resp_text),
    response_text: resp_text,
    response_bytes: resp_bytes,
    negotiated_suite: suite,
    resumed,
    handshake_wire_in: hs_in,
    handshake_wire_out: hs_out,
    exported_session: exported,
  }
}

///|
/// Builds a standard HTTP/1.1 request with accurate `Content-Length`.
pub fn build_http_request(
  http_method : String,
  path : String,
  body : String,
) -> Bytes {
  let body_bytes = @utf8.encode(body)
  let header = http_method +
    " " +
    path +
    " HTTP/1.1\r\n" +
    "Host: tlcp-proxy.local\r\n" +
    "Content-Length: " +
    body_bytes.length().to_string() +
    "\r\n" +
    "Connection: close\r\n\r\n"
  concat_bytes([@utf8.encode(header), body_bytes])
}
