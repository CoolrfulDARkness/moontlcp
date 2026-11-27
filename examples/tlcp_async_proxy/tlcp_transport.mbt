///|
/// Native asynchronous GM/T 0024-2023 (TLCP 1.1) TCP transport wrapper built on
/// `moonbitlang/async/socket` (`Tcp` / `TcpServer`) and the zero-dependency
/// Sans-I/O `CoolrfulDARkness/moontlcp` state machine.

///|
#derive(Eq, Debug)
pub suberror ProxyError {
  HandshakeFailed(String)
  ProtocolRejected(String)
  PeerClosedUnexpectedly
  HttpParseError(String)
  ConfigError(String)
}

///|
pub(all) struct PemPkiBundle {
  ca_pem : String
  server_dual_pem : String
  client_dual_pem : String
  server_sign_priv : @sm2.PrivateKey
  server_enc_priv : @sm2.PrivateKey
  client_sign_priv : @sm2.PrivateKey
  client_enc_priv : @sm2.PrivateKey
}

///|
pub(all) struct VerifiedDualCerts {
  sign_cert : @x509.Certificate
  enc_cert : @x509.Certificate
  trust_anchors : Array[@x509.Certificate]
}

///|
fn format_x509_error(err : @x509.X509Error) -> String {
  match err {
    @x509.DerError(msg) => "DerError(" + msg + ")"
    @x509.UnsupportedVersion => "UnsupportedVersion"
    @x509.UnsupportedAlgorithm(oid) => "UnsupportedAlgorithm(" + oid + ")"
    @x509.InvalidPublicKey => "InvalidPublicKey"
    @x509.InvalidSignature => "InvalidSignature"
    @x509.NotCa => "NotCa"
    @x509.BadKeyUsage(msg) => "BadKeyUsage(" + msg + ")"
    @x509.ChainVerificationFailed(msg) => "ChainVerificationFailed(" + msg + ")"
    @x509.DualCertMismatch(msg) => "DualCertMismatch(" + msg + ")"
    @x509.InvalidCertCount(n) => "InvalidCertCount(" + n.to_string() + ")"
  }
}

///|
/// Deterministically generates a GM SM2 X.509 v3 test PKI and serializes the
/// Root CA, server `[sign, enc]` dual-cert chain, and client `[sign, enc]`
/// dual-cert chain into standard PEM strings.
pub fn export_test_pki_pem(seed : Bytes) -> PemPkiBundle raise ProxyError {
  let pki = @moontlcp.generate_test_pki(seed) catch {
    e => raise ConfigError("generate_test_pki failed: " + format_x509_error(e))
  }
  {
    ca_pem: pki.ca_cert.to_pem(),
    server_dual_pem: pki.server_sign_cert.to_pem() +
    "\n" +
    pki.server_enc_cert.to_pem(),
    client_dual_pem: pki.client_sign_cert.to_pem() +
    "\n" +
    pki.client_enc_cert.to_pem(),
    server_sign_priv: pki.server_sign_priv,
    server_enc_priv: pki.server_enc_priv,
    client_sign_priv: pki.client_sign_priv,
    client_enc_priv: pki.client_enc_priv,
  }
}

///|
/// Parses a PEM trust-anchor bundle and a PEM `[sign, enc, ...intermediates]`
/// dual-certificate chain, then enforces GM/T 0024-2023 KeyUsage separation and
/// cryptographic chain verification before returning the verified bundle.
pub fn load_dual_certs_from_pem(
  dual_cert_pem : String,
  ca_pem : String,
) -> VerifiedDualCerts raise ProxyError {
  let ca_certs = @moontlcp.parse_certs_pem(ca_pem) catch {
    e => raise ConfigError("invalid CA PEM: " + format_x509_error(e))
  }
  if ca_certs.is_empty() {
    raise ConfigError("CA PEM contains no certificates")
  }
  let parsed = @moontlcp.parse_certs_pem(dual_cert_pem) catch {
    e => raise ConfigError("invalid dual-cert PEM: " + format_x509_error(e))
  }
  if parsed.length() < 2 {
    raise ConfigError(
      "dual-cert PEM must contain at least 2 certificates (sign + enc)",
    )
  }
  let der_chain : Array[Bytes] = []
  for cert in parsed {
    der_chain.push(cert.raw_der)
  }
  let verified = @moontlcp.verify_dual_certs(der_chain, ca_certs) catch {
    e =>
      raise ConfigError(
        "dual-cert chain verification failed: " + format_x509_error(e),
      )
  }
  {
    sign_cert: verified.sign_cert,
    enc_cert: verified.enc_cert,
    trust_anchors: ca_certs,
  }
}

///|
fn append_bytes_to_buf(buf : Array[Byte], data : Bytes) -> Unit {
  for i in 0..<data.length() {
    buf.push(data[i])
  }
}

///|
fn drain_byte_buf(buf : Array[Byte]) -> Bytes {
  let out = Bytes::from_array(buf[:])
  buf.clear()
  out
}

///|
fn concat_bytes(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for p in parts {
    total += p.length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut off = 0
  for p in parts {
    for i in 0..<p.length() {
      out[off + i] = p[i]
    }
    off += p.length()
  }
  Bytes::from_array(out)
}

///|
fn format_state_error(err : @state.StateError) -> String {
  match err {
    @state.ProtocolError(alert, msg) =>
      "ProtocolError(" + alert.name() + "): " + msg
    @state.RecordError(msg) => "RecordError: " + msg
    @state.CertificateError(msg) => "CertificateError: " + msg
    @state.CryptoError(msg) => "CryptoError: " + msg
    @state.InvalidState(msg) => "InvalidState: " + msg
  }
}

///|
async fn best_effort_write(sock : @socket.Tcp, data : Bytes) -> Unit {
  if data.length() == 0 {
    return
  }
  sock.write(data) catch {
    _ => ()
  }
}

///|
/// Established server-side TLCP 1.1 stream running over a native OS TCP socket.
pub struct AsyncTlcpServerStream {
  sock : @socket.Tcp
  conn : @state.ServerConn
  app_buf : Array[Byte]
  mut peer_closed : Bool
  mut wire_bytes_in : Int32
  mut wire_bytes_out : Int32
}

///|
/// Drives a server-side TLCP 1.1 handshake to completion over `sock`.
/// On protocol failure, any pending Fatal Alert record produced by the state
/// machine is flushed onto the TCP socket before raising `ProxyError`.
pub async fn AsyncTlcpServerStream::accept(
  sock : @socket.Tcp,
  config : @state.ServerConfig,
) -> AsyncTlcpServerStream {
  let conn = @moontlcp.new_server(config)
  let app_buf : Array[Byte] = []
  let mut peer_closed = false
  let mut wire_in = 0
  let mut wire_out = 0
  while !conn.is_established() {
    match sock.read_some() {
      None => raise PeerClosedUnexpectedly
      Some(chunk) => {
        wire_in += chunk.length()
        let events = conn.feed(chunk[:]) catch {
          err => {
            let alert_wire = conn.take_outbound()
            best_effort_write(sock, alert_wire)
            raise ProtocolRejected(format_state_error(err))
          }
        }
        let outbound = conn.take_outbound()
        if outbound.length() > 0 {
          wire_out += outbound.length()
          sock.write(outbound)
        }
        for ev in events {
          match ev {
            @state.ApplicationData(d) => append_bytes_to_buf(app_buf, d)
            @state.PeerClosed => peer_closed = true
            _ => ()
          }
        }
      }
    }
  }
  {
    sock,
    conn,
    app_buf,
    peer_closed,
    wire_bytes_in: wire_in,
    wire_bytes_out: wire_out,
  }
}

///|
/// Reads the next chunk of decrypted application data from the client.
/// Returns `None` on clean `close_notify` or EOF; flushes a Fatal Alert and
/// raises `ProxyError::ProtocolRejected` if record authentication fails.
pub async fn AsyncTlcpServerStream::read_app_data(
  self : AsyncTlcpServerStream,
) -> Bytes? {
  if self.app_buf.length() > 0 {
    return Some(drain_byte_buf(self.app_buf))
  }
  if self.peer_closed {
    return None
  }
  for ;; {
    match self.sock.read_some() {
      None => {
        self.peer_closed = true
        return None
      }
      Some(chunk) => {
        self.wire_bytes_in += chunk.length()
        let events = self.conn.feed(chunk[:]) catch {
          err => {
            let alert_wire = self.conn.take_outbound()
            best_effort_write(self.sock, alert_wire)
            raise ProtocolRejected(format_state_error(err))
          }
        }
        let outbound = self.conn.take_outbound()
        if outbound.length() > 0 {
          self.wire_bytes_out += outbound.length()
          self.sock.write(outbound)
        }
        for ev in events {
          match ev {
            @state.ApplicationData(d) => append_bytes_to_buf(self.app_buf, d)
            @state.PeerClosed => self.peer_closed = true
            _ => ()
          }
        }
        if self.app_buf.length() > 0 {
          return Some(drain_byte_buf(self.app_buf))
        }
        if self.peer_closed {
          return None
        }
      }
    }
  }
}

///|
/// Encrypts `data` into TLCP 1.1 record(s) (auto-fragmented at 16 KiB) and
/// transmits them over the underlying OS TCP socket.
pub async fn AsyncTlcpServerStream::write_app_data(
  self : AsyncTlcpServerStream,
  data : Bytes,
) -> Unit {
  if data.length() == 0 {
    return
  }
  let wire = self.conn.write_app_data(data) catch {
    err => raise ProtocolRejected(format_state_error(err))
  }
  self.wire_bytes_out += wire.length()
  self.sock.write(wire)
}

///|
/// Best-effort transmission of an encrypted TLCP `close_notify` alert.
pub async fn AsyncTlcpServerStream::close_notify(
  self : AsyncTlcpServerStream,
) -> Unit {
  let alert_wire = self.conn.close_notify() catch { _ => b"" }
  if alert_wire.length() > 0 {
    self.wire_bytes_out += alert_wire.length()
    best_effort_write(self.sock, alert_wire)
  }
}

///|
pub fn AsyncTlcpServerStream::negotiated_suite(
  self : AsyncTlcpServerStream,
) -> @handshake.CipherSuite? {
  self.conn.negotiated_suite()
}

///|
pub fn AsyncTlcpServerStream::is_resumed(self : AsyncTlcpServerStream) -> Bool {
  self.conn.is_resumed()
}

///|
pub fn AsyncTlcpServerStream::peer_certs(
  self : AsyncTlcpServerStream,
) -> @x509.DualCertBundle? {
  self.conn.peer_certs()
}

///|
pub fn AsyncTlcpServerStream::wire_in(self : AsyncTlcpServerStream) -> Int32 {
  self.wire_bytes_in
}

///|
pub fn AsyncTlcpServerStream::wire_out(self : AsyncTlcpServerStream) -> Int32 {
  self.wire_bytes_out
}

///|
/// Established client-side TLCP 1.1 stream running over a native OS TCP socket.
pub struct AsyncTlcpClientStream {
  sock : @socket.Tcp
  conn : @state.ClientConn
  app_buf : Array[Byte]
  mut peer_closed : Bool
  mut wire_bytes_in : Int32
  mut wire_bytes_out : Int32
}

///|
/// Connects to `addr` over OS TCP and completes a TLCP 1.1 handshake.
pub async fn AsyncTlcpClientStream::connect(
  addr : @socket.Addr,
  config : @state.ClientConfig,
) -> AsyncTlcpClientStream {
  let sock = @socket.Tcp::connect(addr)
  errdefer sock.close()
  let conn = @moontlcp.new_client(config)
  let app_buf : Array[Byte] = []
  let mut peer_closed = false
  let mut wire_in = 0
  let mut wire_out = 0
  let initial = conn.start_handshake() catch {
    err => raise HandshakeFailed(format_state_error(err))
  }
  wire_out += initial.length()
  sock.write(initial)
  while !conn.is_established() {
    match sock.read_some() {
      None => raise PeerClosedUnexpectedly
      Some(chunk) => {
        wire_in += chunk.length()
        let events = conn.feed(chunk[:]) catch {
          err => {
            let alert_wire = conn.take_outbound()
            best_effort_write(sock, alert_wire)
            raise ProtocolRejected(format_state_error(err))
          }
        }
        let outbound = conn.take_outbound()
        if outbound.length() > 0 {
          wire_out += outbound.length()
          sock.write(outbound)
        }
        for ev in events {
          match ev {
            @state.ApplicationData(d) => append_bytes_to_buf(app_buf, d)
            @state.PeerClosed => peer_closed = true
            _ => ()
          }
        }
      }
    }
  }
  {
    sock,
    conn,
    app_buf,
    peer_closed,
    wire_bytes_in: wire_in,
    wire_bytes_out: wire_out,
  }
}

///|
pub async fn AsyncTlcpClientStream::read_app_data(
  self : AsyncTlcpClientStream,
) -> Bytes? {
  if self.app_buf.length() > 0 {
    return Some(drain_byte_buf(self.app_buf))
  }
  if self.peer_closed {
    return None
  }
  for ;; {
    match self.sock.read_some() {
      None => {
        self.peer_closed = true
        return None
      }
      Some(chunk) => {
        self.wire_bytes_in += chunk.length()
        let events = self.conn.feed(chunk[:]) catch {
          err => {
            let alert_wire = self.conn.take_outbound()
            best_effort_write(self.sock, alert_wire)
            raise ProtocolRejected(format_state_error(err))
          }
        }
        let outbound = self.conn.take_outbound()
        if outbound.length() > 0 {
          self.wire_bytes_out += outbound.length()
          self.sock.write(outbound)
        }
        for ev in events {
          match ev {
            @state.ApplicationData(d) => append_bytes_to_buf(self.app_buf, d)
            @state.PeerClosed => self.peer_closed = true
            _ => ()
          }
        }
        if self.app_buf.length() > 0 {
          return Some(drain_byte_buf(self.app_buf))
        }
        if self.peer_closed {
          return None
        }
      }
    }
  }
}

///|
pub async fn AsyncTlcpClientStream::write_app_data(
  self : AsyncTlcpClientStream,
  data : Bytes,
) -> Unit {
  if data.length() == 0 {
    return
  }
  let wire = self.conn.write_app_data(data) catch {
    err => raise ProtocolRejected(format_state_error(err))
  }
  self.wire_bytes_out += wire.length()
  self.sock.write(wire)
}

///|
/// Encrypts `data` into raw TLCP record wire bytes without writing to the
/// socket. Useful for red-team ciphertext tampering tests.
pub fn AsyncTlcpClientStream::seal_record_bytes(
  self : AsyncTlcpClientStream,
  data : Bytes,
) -> Bytes raise ProxyError {
  self.conn.write_app_data(data) catch {
    err => raise ProtocolRejected(format_state_error(err))
  }
}

///|
pub fn AsyncTlcpClientStream::raw_socket(
  self : AsyncTlcpClientStream,
) -> @socket.Tcp {
  self.sock
}

///|
pub async fn AsyncTlcpClientStream::close(self : AsyncTlcpClientStream) -> Unit {
  let alert_wire = self.conn.close_notify() catch { _ => b"" }
  if alert_wire.length() > 0 {
    self.wire_bytes_out += alert_wire.length()
    best_effort_write(self.sock, alert_wire)
  }
  self.sock.close()
}

///|
pub fn AsyncTlcpClientStream::close_socket_now(
  self : AsyncTlcpClientStream,
) -> Unit {
  self.sock.close()
}

///|
pub fn AsyncTlcpClientStream::export_session(
  self : AsyncTlcpClientStream,
) -> @state.ResumedSession? {
  self.conn.export_session()
}

///|
pub fn AsyncTlcpClientStream::negotiated_suite(
  self : AsyncTlcpClientStream,
) -> @handshake.CipherSuite? {
  self.conn.negotiated_suite()
}

///|
pub fn AsyncTlcpClientStream::is_resumed(self : AsyncTlcpClientStream) -> Bool {
  self.conn.is_resumed()
}

///|
pub fn AsyncTlcpClientStream::wire_in(self : AsyncTlcpClientStream) -> Int32 {
  self.wire_bytes_in
}

///|
pub fn AsyncTlcpClientStream::wire_out(self : AsyncTlcpClientStream) -> Int32 {
  self.wire_bytes_out
}
