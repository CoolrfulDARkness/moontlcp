///|
/// Sans-I/O GM/T 0024-2023 (GB/T 38636-2020) TLCP 1.1 Server State Machine.

///|
#derive(Eq)
enum ServerState {
  WaitClientHello
  WaitClientCert
  WaitClientKeyExchange
  WaitClientCertVerify
  WaitClientChangeCipherSpec
  WaitClientFinished
  Established
  Failed
}

///|
/// Sans-I/O TLCP 1.1 server connection.
pub struct ServerConn {
  config : ServerConfig
  prng : Prng
  mut state : ServerState
  read_layer : @record.RecordLayer
  write_layer : @record.RecordLayer
  mut write_encrypted : Bool
  inbound : Array[Byte]
  hs_buf : Array[Byte]
  outbound : Array[Byte]
  transcript : @handshake.Transcript
  mut client_random : Bytes
  mut server_random : Bytes
  mut session_id : Bytes
  mut suite : @handshake.CipherSuite?
  mut peer_bundle : @x509.DualCertBundle?
  mut server_eph_priv : @sm2.PrivateKey?
  mut client_cert_requested : Bool
  mut master_secret : Bytes
  mut key_block : @handshake.KeyBlock?
  mut resumed : Bool
  mut local_closed : Bool
  mut peer_closed : Bool
}

///|
/// Creates a new `ServerConn` waiting for a `ClientHello`.
pub fn ServerConn::new(config : ServerConfig) -> ServerConn {
  {
    prng: Prng::new(config.seed),
    config,
    state: WaitClientHello,
    read_layer: @record.RecordLayer::new(),
    write_layer: @record.RecordLayer::new(),
    write_encrypted: false,
    inbound: [],
    hs_buf: [],
    outbound: [],
    transcript: @handshake.Transcript::new(),
    client_random: b"",
    server_random: b"",
    session_id: b"",
    suite: None,
    peer_bundle: None,
    server_eph_priv: None,
    client_cert_requested: false,
    master_secret: b"",
    key_block: None,
    resumed: false,
    local_closed: false,
    peer_closed: false,
  }
}

///|
pub fn ServerConn::is_established(self : ServerConn) -> Bool {
  self.state == Established
}

///|
pub fn ServerConn::is_failed(self : ServerConn) -> Bool {
  self.state == Failed
}

///|
pub fn ServerConn::is_resumed(self : ServerConn) -> Bool {
  self.resumed
}

///|
pub fn ServerConn::negotiated_suite(
  self : ServerConn,
) -> @handshake.CipherSuite? {
  self.suite
}

///|
pub fn ServerConn::peer_certs(self : ServerConn) -> @x509.DualCertBundle? {
  self.peer_bundle
}

///|
pub fn ServerConn::session_id(self : ServerConn) -> Bytes {
  self.session_id
}

///|
pub fn ServerConn::export_session(self : ServerConn) -> ResumedSession? {
  if !self.is_established() ||
    self.session_id.length() == 0 ||
    self.master_secret.length() != 48 {
    return None
  }
  match self.suite {
    Some(s) =>
      Some({
        session_id: self.session_id,
        cipher_suite: s,
        master_secret: self.master_secret,
      })
    None => None
  }
}

///|
/// Drains and returns all queued outbound wire bytes (handshake flights or
/// Fatal Alerts emitted during `feed`).
pub fn ServerConn::take_outbound(self : ServerConn) -> Bytes {
  drain_buffer(self.outbound)
}

///|
fn ServerConn::seal_fragment(
  self : ServerConn,
  ct : @record.ContentType,
  plaintext : Bytes,
) -> Bytes raise StateError {
  let iv = if self.write_encrypted {
    self.prng.next_explicit_iv(self.suite)
  } else {
    b""
  }
  self.write_layer.seal(ct, plaintext, iv) catch {
    err => {
      let (_, msg) = record_err_to_alert(err)
      self.state = Failed
      raise RecordError(msg)
    }
  }
}

///|
fn ServerConn::queue_fatal_alert(
  self : ServerConn,
  desc : @handshake.AlertDescription,
) -> Unit {
  if self.state == Failed {
    return
  }
  let payload = @handshake.encode_alert({
    level: @handshake.Fatal,
    description: desc,
  })
  let iv = if self.write_encrypted {
    self.prng.next_explicit_iv(self.suite)
  } else {
    b""
  }
  let wire = Some(self.write_layer.seal(@record.Alert, payload, iv)) catch {
    _ => None
  }
  match wire {
    Some(b) => append_bytes(self.outbound, b)
    None => ()
  }
  self.state = Failed
}

///|
fn ServerConn::fail_protocol(
  self : ServerConn,
  desc : @handshake.AlertDescription,
  msg : String,
) -> Unit raise StateError {
  self.queue_fatal_alert(desc)
  raise ProtocolError(desc, msg)
}

///|
fn ServerConn::fail_cert(
  self : ServerConn,
  desc : @handshake.AlertDescription,
  msg : String,
) -> Unit raise StateError {
  self.queue_fatal_alert(desc)
  raise CertificateError(msg)
}

///|
fn ServerConn::fail_crypto(
  self : ServerConn,
  desc : @handshake.AlertDescription,
  msg : String,
) -> Unit raise StateError {
  self.queue_fatal_alert(desc)
  raise CryptoError(msg)
}

///|
fn ServerConn::queue_handshake_msg(
  self : ServerConn,
  msg : @handshake.HandshakeMsg,
  target : Array[Byte],
) -> Unit raise StateError {
  let encoded = @handshake.encode_handshake_msg(msg)
  self.transcript.update(encoded)
  let frags = @record.fragment_plaintext(@record.Handshake, encoded)
  for i = 0; i < frags.length(); i = i + 1 {
    let wire = self.seal_fragment(@record.Handshake, frags[i].payload)
    append_bytes(target, wire)
  }
}

///|
/// Encrypts application data (automatically fragmenting into <= 16KB TLCP
/// records) and returns the wire bytes.
pub fn ServerConn::write_app_data(
  self : ServerConn,
  data : Bytes,
) -> Bytes raise StateError {
  if self.state == Failed {
    raise InvalidState("server connection is in failed state")
  }
  if self.state != Established {
    raise InvalidState(
      "cannot write application data before handshake completes",
    )
  }
  if self.local_closed {
    raise InvalidState("connection already closed locally")
  }
  if data.length() == 0 {
    return b""
  }
  let frags = @record.fragment_plaintext(@record.ApplicationData, data)
  let out : Array[Byte] = []
  for i = 0; i < frags.length(); i = i + 1 {
    let wire = self.seal_fragment(@record.ApplicationData, frags[i].payload)
    append_bytes(out, wire)
  }
  Bytes::from_array(out)
}

///|
/// Emits a `Warning / CloseNotify` alert record and marks the local write half closed.
pub fn ServerConn::close_notify(self : ServerConn) -> Bytes raise StateError {
  if self.state == Failed {
    raise InvalidState("server connection is in failed state")
  }
  if self.local_closed {
    raise InvalidState("close_notify already sent")
  }
  let payload = @handshake.encode_alert({
    level: @handshake.Warning,
    description: @handshake.CloseNotify,
  })
  let wire = self.seal_fragment(@record.Alert, payload)
  self.local_closed = true
  wire
}

///|
fn u16_array_contains(arr : Array[UInt32], target : UInt32) -> Bool {
  for i = 0; i < arr.length(); i = i + 1 {
    if arr[i] == target {
      return true
    }
  }
  false
}

///|
fn ServerConn::select_cipher_suite(
  self : ServerConn,
  client_suites : Array[UInt32],
) -> @handshake.CipherSuite? {
  for i = 0; i < self.config.cipher_suites.length(); i = i + 1 {
    let s = self.config.cipher_suites[i]
    if u16_array_contains(client_suites, s.to_u16()) {
      return Some(s)
    }
  }
  None
}

///|
fn ServerConn::suite_allowed(
  self : ServerConn,
  suite : @handshake.CipherSuite,
) -> Bool {
  for i = 0; i < self.config.cipher_suites.length(); i = i + 1 {
    if self.config.cipher_suites[i] == suite {
      return true
    }
  }
  false
}

///|
fn ServerConn::send_ccs_and_finished(
  self : ServerConn,
  suite : @handshake.CipherSuite,
  ms : Bytes,
  kb : @handshake.KeyBlock,
) -> Unit raise StateError {
  let ccs_wire = self.seal_fragment(@record.ChangeCipherSpec, b"\x01")
  append_bytes(self.outbound, ccs_wire)
  let cipher = make_cipher_state(suite, kb, false)
  self.write_layer.set_cipher(cipher)
  self.write_encrypted = true
  let vd = @handshake.compute_verify_data(ms, false, self.transcript.hash())
  self.queue_handshake_msg(
    @handshake.Finished({ verify_data: vd, }),
    self.outbound,
  )
}

///|
fn parse_client_ecdhe_pubkey(params : Bytes) -> @sm2.PublicKey raise StateError {
  let parsed = Some(@handshake.parse_ecdhe_params(params[:])) catch {
    _ => None
  }
  match parsed {
    Some((_, pub_bytes)) =>
      @sm2.PublicKey::from_bytes(pub_bytes) catch {
        err => raise CryptoError(sm2_err_to_msg(err))
      }
    None =>
      if params.length() == 66 && params[0] == b'\x41' {
        let raw = FixedArray::make(65, b'\x00')
        for i = 0; i < 65; i = i + 1 {
          raw[i] = params[1 + i]
        }
        @sm2.PublicKey::from_bytes(Bytes::from_array(raw)) catch {
          err => raise CryptoError(sm2_err_to_msg(err))
        }
      } else if params.length() == 65 {
        @sm2.PublicKey::from_bytes(params) catch {
          err => raise CryptoError(sm2_err_to_msg(err))
        }
      } else {
        raise ProtocolError(
          @handshake.IllegalParameter,
          "malformed client ECDHE key exchange parameters",
        )
      }
  }
}

///|
fn ServerConn::handle_client_hello(
  self : ServerConn,
  raw_frame : Bytes,
  ch : @handshake.ClientHello,
) -> Unit raise StateError {
  if !bytes_contains(ch.compression_methods, b'\x00') {
    self.fail_protocol(
      @handshake.IllegalParameter,
      "client does not support null compression",
    )
  }
  self.transcript.update(raw_frame)
  self.client_random = ch.random
  self.server_random = self.prng.next_bytes(b"server-random", 32)
  // Attempt Session ID resumption if session_store matches
  match self.config.session_store {
    Some(store) =>
      match store.get(ch.session_id) {
        Some(rs) =>
          if self.suite_allowed(rs.cipher_suite) &&
            u16_array_contains(ch.cipher_suites, rs.cipher_suite.to_u16()) {
            self.resumed = true
            self.session_id = rs.session_id
            self.suite = Some(rs.cipher_suite)
            self.master_secret = rs.master_secret
            let sh = @handshake.ServerHello::{
              version_major: @record.TLCP_VERSION_MAJOR,
              version_minor: @record.TLCP_VERSION_MINOR,
              random: self.server_random,
              session_id: rs.session_id,
              cipher_suite: rs.cipher_suite,
              compression_method: b'\x00',
            }
            self.queue_handshake_msg(@handshake.ServerHello(sh), self.outbound)
            let kb = @handshake.derive_key_block(
              rs.master_secret,
              self.server_random,
              self.client_random,
              rs.cipher_suite,
            )
            self.key_block = Some(kb)
            self.send_ccs_and_finished(rs.cipher_suite, rs.master_secret, kb)
            self.state = WaitClientChangeCipherSpec
            return
          }
        None => ()
      }
    None => ()
  }
  // Full handshake cipher suite negotiation
  let suite = match self.select_cipher_suite(ch.cipher_suites) {
    Some(s) => s
    None => {
      self.fail_protocol(
        @handshake.HandshakeFailure,
        "no mutually supported TLCP 1.1 cipher suite",
      )
      return
    }
  }
  self.suite = Some(suite)
  self.session_id = self.prng.next_bytes(b"server-session-id", 32)
  // 1. ServerHello
  let sh = @handshake.ServerHello::{
    version_major: @record.TLCP_VERSION_MAJOR,
    version_minor: @record.TLCP_VERSION_MINOR,
    random: self.server_random,
    session_id: self.session_id,
    cipher_suite: suite,
    compression_method: b'\x00',
  }
  self.queue_handshake_msg(@handshake.ServerHello(sh), self.outbound)
  // 2. Certificate (dual-cert: sign_cert, enc_cert)
  let cert_msg = @handshake.CertificateMsg::{
    certificates: [self.config.sign_cert.raw_der, self.config.enc_cert.raw_der],
  }
  self.queue_handshake_msg(@handshake.Certificate(cert_msg), self.outbound)
  // 3. ServerKeyExchange (ECC or ECDHE)
  if !suite.is_ecdhe() {
    let tbs = @handshake.build_ecc_ske_tbs(
      self.client_random,
      self.server_random,
      self.config.enc_cert.raw_der,
    )
    let sig = @sm2.sign_der(self.config.sign_priv, @sm2.DEFAULT_SM2_ID, tbs) catch {
      err => {
        self.fail_crypto(@handshake.InternalError, sm2_err_to_msg(err))
        b""
      }
    }
    self.queue_handshake_msg(
      @handshake.ServerKeyExchange(@handshake.ServerKeyExchange::Ecc(sig)),
      self.outbound,
    )
  } else {
    let eph_seed = self.prng.next_bytes(b"server-ecdhe-eph", 32)
    let s_eph_priv = @sm2.derive_keypair_from_seed(eph_seed) catch {
      err => {
        self.fail_crypto(@handshake.InternalError, sm2_err_to_msg(err))
        abort("unreachable")
      }
    }
    let params = @handshake.build_ecdhe_params(
      @handshake.NAMED_CURVE_SM2P256V1,
      s_eph_priv.public_key().to_uncompressed_bytes(),
    )
    let tbs = @handshake.build_ecdhe_ske_tbs(
      self.client_random,
      self.server_random,
      params,
    )
    let sig = @sm2.sign_der(self.config.sign_priv, @sm2.DEFAULT_SM2_ID, tbs) catch {
      err => {
        self.fail_crypto(@handshake.InternalError, sm2_err_to_msg(err))
        b""
      }
    }
    self.server_eph_priv = Some(s_eph_priv)
    self.queue_handshake_msg(
      @handshake.ServerKeyExchange(
        @handshake.ServerKeyExchange::Ecdhe(params, sig),
      ),
      self.outbound,
    )
  }
  // 4. CertificateRequest (required for mTLCP or ECDHE SM2 key exchange)
  let need_client_cert = self.config.require_client_cert || suite.is_ecdhe()
  if need_client_cert {
    self.client_cert_requested = true
    let cr = @handshake.CertificateRequest::{
      cert_types: b"\x40",
      ca_names: [],
    }
    self.queue_handshake_msg(@handshake.CertificateRequest(cr), self.outbound)
  }
  // 5. ServerHelloDone
  self.queue_handshake_msg(@handshake.ServerHelloDone, self.outbound)
  self.state = if need_client_cert {
    WaitClientCert
  } else {
    WaitClientKeyExchange
  }
}

///|
fn ServerConn::handle_handshake_msg(
  self : ServerConn,
  raw_frame : Bytes,
  msg : @handshake.HandshakeMsg,
  events : Array[Event],
) -> Unit raise StateError {
  match (self.state, msg) {
    (WaitClientHello, @handshake.ClientHello(ch)) =>
      self.handle_client_hello(raw_frame, ch)
    (WaitClientCert, @handshake.Certificate(cert_msg)) => {
      self.transcript.update(raw_frame)
      if cert_msg.certificates.length() == 0 {
        self.fail_cert(
          @handshake.BadCertificate,
          "client sent empty certificate list when mTLCP/ECDHE requires dual certs",
        )
      }
      let bundle = @x509.parse_and_verify_dual_certs(
        cert_msg.certificates,
        self.config.client_trust_anchors,
      ) catch {
        err => {
          let (alert, msg_str) = x509_err_to_alert(err)
          self.fail_cert(alert, msg_str)
          abort("unreachable")
        }
      }
      self.peer_bundle = Some(bundle)
      self.state = WaitClientKeyExchange
    }
    (WaitClientKeyExchange, @handshake.ClientKeyExchange(cke)) => {
      self.transcript.update(raw_frame)
      let suite = match self.suite {
        Some(s) => s
        None => {
          self.fail_protocol(@handshake.InternalError, "missing suite")
          return
        }
      }
      let pms = match cke {
        @handshake.ClientKeyExchange::Ecc(ct_asn1) => {
          let decrypted = @sm2.decrypt_asn1(self.config.enc_priv, ct_asn1) catch {
            err => {
              self.fail_crypto(@handshake.DecryptError, sm2_err_to_msg(err))
              b""
            }
          }
          if decrypted.length() != 48 ||
            decrypted[0] != @record.TLCP_VERSION_MAJOR ||
            decrypted[1] != @record.TLCP_VERSION_MINOR {
            self.fail_protocol(
              @handshake.DecryptError,
              "invalid TLCP pre_master_secret length or version",
            )
          }
          decrypted
        }
        @handshake.ClientKeyExchange::Ecdhe(params) => {
          let client_bundle = match self.peer_bundle {
            Some(b) => b
            None => {
              self.fail_protocol(
                @handshake.UnexpectedMessage,
                "ECDHE requires verified client dual certificates",
              )
              abort("unreachable")
            }
          }
          let s_eph_priv = match self.server_eph_priv {
            Some(k) => k
            None => {
              self.fail_protocol(
                @handshake.InternalError,
                "missing server ECDHE ephemeral key",
              )
              abort("unreachable")
            }
          }
          let c_eph_pub = parse_client_ecdhe_pubkey(params) catch {
            ProtocolError(desc, m) => {
              self.fail_protocol(desc, m)
              abort("unreachable")
            }
            CryptoError(m) => {
              self.fail_crypto(@handshake.IllegalParameter, m)
              abort("unreachable")
            }
            other => {
              self.queue_fatal_alert(@handshake.InternalError)
              raise other
            }
          }
          let ke = @sm2.key_exchange_initiator(
            @sm2.DEFAULT_SM2_ID,
            self.config.enc_priv,
            s_eph_priv,
            @sm2.DEFAULT_SM2_ID,
            client_bundle.enc_cert.public_key,
            c_eph_pub,
            48,
          ) catch {
            err => {
              self.fail_crypto(@handshake.DecryptError, sm2_err_to_msg(err))
              abort("unreachable")
            }
          }
          ke.shared_key
        }
      }
      let ms = @handshake.derive_master_secret(
        pms,
        self.client_random,
        self.server_random,
      )
      let kb = @handshake.derive_key_block(
        ms,
        self.server_random,
        self.client_random,
        suite,
      )
      self.master_secret = ms
      self.key_block = Some(kb)
      self.state = if self.client_cert_requested {
        WaitClientCertVerify
      } else {
        WaitClientChangeCipherSpec
      }
    }
    (WaitClientCertVerify, @handshake.CertificateVerify(cv)) => {
      let client_bundle = match self.peer_bundle {
        Some(b) => b
        None => {
          self.fail_protocol(
            @handshake.InternalError,
            "missing client certificate for CertificateVerify",
          )
          return
        }
      }
      if !@sm2.verify_der(
          client_bundle.sign_cert.public_key,
          @sm2.DEFAULT_SM2_ID,
          self.transcript.raw_bytes(),
          cv.signature,
        ) {
        self.fail_crypto(
          @handshake.DecryptError,
          "invalid client CertificateVerify signature",
        )
      }
      self.transcript.update(raw_frame)
      self.state = WaitClientChangeCipherSpec
    }
    (WaitClientFinished, @handshake.Finished(fin)) => {
      let expected = @handshake.compute_verify_data(
        self.master_secret,
        true,
        self.transcript.hash(),
      )
      if !@ct.ct_eq(fin.verify_data, expected) {
        self.fail_protocol(
          @handshake.DecryptError,
          "client Finished verify_data mismatch",
        )
      }
      self.transcript.update(raw_frame)
      let suite = match self.suite {
        Some(s) => s
        None => {
          self.fail_protocol(@handshake.InternalError, "missing suite")
          return
        }
      }
      let kb = match self.key_block {
        Some(k) => k
        None => {
          self.fail_protocol(@handshake.InternalError, "missing key block")
          return
        }
      }
      if !self.resumed {
        match self.config.session_store {
          Some(store) =>
            store.put({
              session_id: self.session_id,
              cipher_suite: suite,
              master_secret: self.master_secret,
            })
          None => ()
        }
        self.send_ccs_and_finished(suite, self.master_secret, kb)
      }
      self.state = Established
      events.push(HandshakeComplete)
    }
    _ =>
      self.fail_protocol(
        @handshake.UnexpectedMessage,
        "unexpected handshake message for current server state",
      )
  }
}

///|
fn ServerConn::process_handshake_buf(
  self : ServerConn,
  events : Array[Event],
) -> Unit raise StateError {
  while self.hs_buf.length() > 0 {
    let view_bytes = Bytes::from_array(self.hs_buf)
    let frame_res = Some(@handshake.decode_handshake_frame(view_bytes[:])) catch {
      @handshake.Incomplete => None
      err => {
        let (alert, msg) = handshake_err_to_alert(err)
        self.fail_protocol(alert, msg)
        None
      }
    }
    match frame_res {
      None => break
      Some((msg_type, body, consumed)) => {
        let is_ecdhe = match self.suite {
          Some(s) => s.is_ecdhe()
          None => false
        }
        let msg = @handshake.decode_handshake_msg(msg_type, body, is_ecdhe) catch {
          err => {
            let (alert, msg_str) = handshake_err_to_alert(err)
            self.fail_protocol(alert, msg_str)
            abort("unreachable")
          }
        }
        let raw_arr = FixedArray::make(consumed, b'\x00')
        for i = 0; i < consumed; i = i + 1 {
          raw_arr[i] = view_bytes[i]
        }
        consume_prefix(self.hs_buf, consumed)
        self.handle_handshake_msg(Bytes::from_array(raw_arr), msg, events)
      }
    }
  }
}

///|
fn ServerConn::handle_record(
  self : ServerConn,
  rec : @record.RawRecord,
  events : Array[Event],
) -> Unit raise StateError {
  let pt = self.read_layer.open(rec) catch {
    err => {
      let (alert, msg) = record_err_to_alert(err)
      self.fail_protocol(alert, msg)
      b""
    }
  }
  match rec.content_type {
    @record.Handshake => {
      if pt.length() == 0 {
        self.fail_protocol(
          @handshake.UnexpectedMessage,
          "empty handshake record",
        )
      }
      if self.state == WaitClientChangeCipherSpec || self.state == Established {
        self.fail_protocol(
          @handshake.UnexpectedMessage,
          "unexpected handshake record in current server state",
        )
      }
      append_bytes(self.hs_buf, pt)
      self.process_handshake_buf(events)
    }
    @record.ChangeCipherSpec => {
      if self.state != WaitClientChangeCipherSpec ||
        self.hs_buf.length() != 0 ||
        pt.length() != 1 ||
        pt[0] != b'\x01' {
        self.fail_protocol(
          @handshake.UnexpectedMessage,
          "unexpected or malformed ChangeCipherSpec",
        )
      }
      let suite = match self.suite {
        Some(s) => s
        None => {
          self.fail_protocol(@handshake.InternalError, "missing suite")
          return
        }
      }
      let kb = match self.key_block {
        Some(k) => k
        None => {
          self.fail_protocol(@handshake.InternalError, "missing key block")
          return
        }
      }
      let cipher = make_cipher_state(suite, kb, true)
      self.read_layer.set_cipher(cipher)
      self.state = WaitClientFinished
    }
    @record.Alert => {
      let alert = @handshake.decode_alert(pt[:]) catch {
        err => {
          let (desc, msg) = handshake_err_to_alert(err)
          self.fail_protocol(desc, msg)
          abort("unreachable")
        }
      }
      match alert.level {
        @handshake.Fatal => {
          self.state = Failed
          raise ProtocolError(
            alert.description,
            "received fatal alert from client",
          )
        }
        @handshake.Warning =>
          if alert.description == @handshake.CloseNotify {
            self.peer_closed = true
            events.push(PeerClosed)
          } else {
            events.push(WarningAlert(alert.description))
          }
      }
    }
    @record.ApplicationData => {
      if self.state != Established {
        self.fail_protocol(
          @handshake.UnexpectedMessage,
          "application data received before handshake complete",
        )
      }
      if pt.length() > 0 {
        events.push(ApplicationData(pt))
      }
    }
  }
}

///|
/// Feeds arbitrary incoming TCP/transport bytes (including 1-byte trickle or
/// coalesced multi-record buffers) into the server state machine.
pub fn ServerConn::feed(
  self : ServerConn,
  data : BytesView,
) -> Array[Event] raise StateError {
  if self.state == Failed {
    raise InvalidState("server connection is in failed state")
  }
  append_view(self.inbound, data)
  let events : Array[Event] = []
  while self.inbound.length() > 0 {
    if self.state == Failed {
      break
    }
    let buf = Bytes::from_array(self.inbound)
    let rec_res = Some(@record.decode_record(buf[:])) catch {
      @record.Incomplete => None
      err => {
        let (alert, msg) = record_err_to_alert(err)
        self.fail_protocol(alert, msg)
        None
      }
    }
    match rec_res {
      None => break
      Some((rec, consumed)) => {
        consume_prefix(self.inbound, consumed)
        self.handle_record(rec, events)
      }
    }
  }
  events
}
