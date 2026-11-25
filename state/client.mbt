///|
/// Sans-I/O GM/T 0024-2023 (GB/T 38636-2020) TLCP 1.1 Client State Machine.

///|
#derive(Eq)
enum ClientState {
  Start
  WaitServerHello
  WaitServerCert
  WaitServerKeyExchange
  WaitCertReqOrServerHelloDone
  WaitServerHelloDone
  WaitServerChangeCipherSpec
  WaitServerFinished
  Established
  Failed
}

///|
/// Sans-I/O TLCP 1.1 client connection.
pub struct ClientConn {
  config : ClientConfig
  prng : Prng
  mut state : ClientState
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
  mut server_eph_pub : @sm2.PublicKey?
  mut cert_requested : Bool
  mut master_secret : Bytes
  mut key_block : @handshake.KeyBlock?
  mut resumed : Bool
  mut local_closed : Bool
  mut peer_closed : Bool
}

///|
/// Creates a new `ClientConn` in the `Start` state.
pub fn ClientConn::new(config : ClientConfig) -> ClientConn {
  {
    prng: Prng::new(config.seed),
    config,
    state: Start,
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
    server_eph_pub: None,
    cert_requested: false,
    master_secret: b"",
    key_block: None,
    resumed: false,
    local_closed: false,
    peer_closed: false,
  }
}

///|
pub fn ClientConn::is_established(self : ClientConn) -> Bool {
  self.state == Established
}

///|
pub fn ClientConn::is_failed(self : ClientConn) -> Bool {
  self.state == Failed
}

///|
pub fn ClientConn::is_resumed(self : ClientConn) -> Bool {
  self.resumed
}

///|
pub fn ClientConn::negotiated_suite(
  self : ClientConn,
) -> @handshake.CipherSuite? {
  self.suite
}

///|
pub fn ClientConn::peer_certs(self : ClientConn) -> @x509.DualCertBundle? {
  self.peer_bundle
}

///|
pub fn ClientConn::session_id(self : ClientConn) -> Bytes {
  self.session_id
}

///|
pub fn ClientConn::export_session(self : ClientConn) -> ResumedSession? {
  if !self.is_established() ||
    self.session_id.length() == 0 ||
    self.session_id.length() > 32 ||
    self.master_secret.length() != 48 {
    return None
  }
  match self.suite {
    Some(s) =>
      Some({
        session_id: self.session_id,
        cipher_suite: s,
        master_secret: self.master_secret,
        peer_certs: self.peer_bundle,
      })
    None => None
  }
}

///|
/// Drains and returns all queued outbound wire bytes (handshake responses or
/// Fatal Alerts emitted during `feed`).
pub fn ClientConn::take_outbound(self : ClientConn) -> Bytes {
  drain_buffer(self.outbound)
}

///|
fn ClientConn::seal_fragment(
  self : ClientConn,
  ct : @record.ContentType,
  plaintext : Bytes,
) -> Bytes raise StateError {
  let iv = if self.write_encrypted {
    self.prng.next_explicit_iv(self.suite, self.write_layer.seq_num())
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
fn ClientConn::queue_fatal_alert(
  self : ClientConn,
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
    self.prng.next_explicit_iv(self.suite, self.write_layer.seq_num())
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
fn ClientConn::fail_protocol(
  self : ClientConn,
  desc : @handshake.AlertDescription,
  msg : String,
) -> Unit raise StateError {
  self.queue_fatal_alert(desc)
  raise ProtocolError(desc, msg)
}

///|
fn ClientConn::fail_cert(
  self : ClientConn,
  desc : @handshake.AlertDescription,
  msg : String,
) -> Unit raise StateError {
  self.queue_fatal_alert(desc)
  raise CertificateError(msg)
}

///|
fn ClientConn::fail_crypto(
  self : ClientConn,
  desc : @handshake.AlertDescription,
  msg : String,
) -> Unit raise StateError {
  self.queue_fatal_alert(desc)
  raise CryptoError(msg)
}

///|
fn ClientConn::queue_handshake_msg(
  self : ClientConn,
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
/// Initiates the TLCP 1.1 handshake by encoding and returning the initial
/// `ClientHello` record bytes.
pub fn ClientConn::start_handshake(self : ClientConn) -> Bytes raise StateError {
  if self.state == Failed {
    raise InvalidState("client connection is in failed state")
  }
  if self.state != Start {
    raise InvalidState("handshake already started")
  }
  if self.config.cipher_suites.length() == 0 {
    self.state = Failed
    raise InvalidState("no cipher suites configured")
  }
  self.client_random = self.prng.next_bytes(b"client-random", 32)
  let offer_sid = match self.config.resume_session {
    Some(rs) => {
      if !is_valid_resumed_session(rs) {
        self.state = Failed
        raise InvalidState(
          "invalid resumed session: session_id must be 1..32 bytes and master_secret 48 bytes",
        )
      }
      rs.session_id
    }
    None => b""
  }
  let suites_u16 : Array[UInt32] = Array(
    capacity=self.config.cipher_suites.length(),
  )
  for i = 0; i < self.config.cipher_suites.length(); i = i + 1 {
    suites_u16.push(self.config.cipher_suites[i].to_u16())
  }
  let ch = @handshake.ClientHello::{
    version_major: @record.TLCP_VERSION_MAJOR,
    version_minor: @record.TLCP_VERSION_MINOR,
    random: self.client_random,
    session_id: offer_sid,
    cipher_suites: suites_u16,
    compression_methods: b"\x00",
  }
  let out : Array[Byte] = []
  self.queue_handshake_msg(@handshake.ClientHello(ch), out)
  self.state = WaitServerHello
  Bytes::from_array(out)
}

///|
/// Encrypts application data (automatically fragmenting into <= 16KB TLCP
/// records) and returns the wire bytes.
pub fn ClientConn::write_app_data(
  self : ClientConn,
  data : Bytes,
) -> Bytes raise StateError {
  if self.state == Failed {
    raise InvalidState("client connection is in failed state")
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
pub fn ClientConn::close_notify(self : ClientConn) -> Bytes raise StateError {
  if self.state == Failed {
    raise InvalidState("client connection is in failed state")
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
fn ClientConn::offered_suite(
  self : ClientConn,
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
fn ClientConn::send_client_flight(self : ClientConn) -> Unit raise StateError {
  let suite = match self.suite {
    Some(s) => s
    None => {
      self.fail_protocol(@handshake.InternalError, "missing negotiated suite")
      return
    }
  }
  let server_bundle = match self.peer_bundle {
    Some(b) => b
    None => {
      self.fail_protocol(
        @handshake.InternalError,
        "missing server certificates",
      )
      return
    }
  }
  if suite.is_ecdhe() && !self.cert_requested {
    self.fail_protocol(
      @handshake.UnexpectedMessage,
      "ECDHE suite requires CertificateRequest for SM2 key exchange",
    )
  }
  // 1. Optional/required Client Certificate (dual-cert)
  if self.cert_requested {
    match self.config.client_certs {
      Some((c_sign_cert, _, c_enc_cert, _)) => {
        let cert_msg = @handshake.CertificateMsg::{
          certificates: [c_sign_cert.raw_der, c_enc_cert.raw_der],
        }
        self.queue_handshake_msg(
          @handshake.Certificate(cert_msg),
          self.outbound,
        )
      }
      None =>
        self.fail_protocol(
          @handshake.HandshakeFailure,
          "server requested client dual certificates but none configured",
        )
    }
  }
  // 2. ClientKeyExchange + PreMasterSecret derivation
  let pms = if !suite.is_ecdhe() {
    let rand46 = self.prng.next_bytes(b"client-pms", 46)
    let pms_arr = FixedArray::make(48, b'\x00')
    pms_arr[0] = @record.TLCP_VERSION_MAJOR
    pms_arr[1] = @record.TLCP_VERSION_MINOR
    for i = 0; i < 46; i = i + 1 {
      pms_arr[2 + i] = rand46[i]
    }
    let pms_bytes = Bytes::from_array(pms_arr)
    let enc_seed = self.prng.next_bytes(b"sm2-pms-enc", 32)
    let ct_asn1 = @sm2.encrypt_asn1(
      server_bundle.enc_cert.public_key,
      pms_bytes,
      enc_seed,
    ) catch {
      err => {
        self.fail_crypto(@handshake.InternalError, sm2_err_to_msg(err))
        b""
      }
    }
    self.queue_handshake_msg(
      @handshake.ClientKeyExchange(@handshake.ClientKeyExchange::Ecc(ct_asn1)),
      self.outbound,
    )
    pms_bytes
  } else {
    let (_, _, _, c_enc_priv) = match self.config.client_certs {
      Some(tuple) => tuple
      None => {
        self.fail_protocol(
          @handshake.HandshakeFailure,
          "ECDHE requires client encryption private key",
        )
        abort("unreachable")
      }
    }
    let server_eph = match self.server_eph_pub {
      Some(pk) => pk
      None => {
        self.fail_protocol(
          @handshake.InternalError,
          "missing server ECDHE ephemeral public key",
        )
        abort("unreachable")
      }
    }
    let eph_seed = self.prng.next_bytes(b"client-ecdhe-eph", 32)
    let c_eph_priv = @sm2.derive_keypair_from_seed(eph_seed) catch {
      err => {
        self.fail_crypto(@handshake.InternalError, sm2_err_to_msg(err))
        abort("unreachable")
      }
    }
    let c_params = @handshake.build_ecdhe_params(
      @handshake.NAMED_CURVE_SM2P256V1,
      c_eph_priv.public_key().to_uncompressed_bytes(),
    )
    self.queue_handshake_msg(
      @handshake.ClientKeyExchange(
        @handshake.ClientKeyExchange::Ecdhe(c_params),
      ),
      self.outbound,
    )
    let ke = @sm2.key_exchange_responder(
      @sm2.DEFAULT_SM2_ID,
      c_enc_priv,
      c_eph_priv,
      @sm2.DEFAULT_SM2_ID,
      server_bundle.enc_cert.public_key,
      server_eph,
      48,
    ) catch {
      err => {
        self.fail_crypto(@handshake.InternalError, sm2_err_to_msg(err))
        abort("unreachable")
      }
    }
    ke.shared_key
  }
  // 3. CertificateVerify (when client cert sent)
  if self.cert_requested {
    let (_, c_sign_priv, _, _) = match self.config.client_certs {
      Some(tuple) => tuple
      None => {
        self.fail_protocol(
          @handshake.InternalError,
          "missing client signing key",
        )
        abort("unreachable")
      }
    }
    let sig = @sm2.sign_der(
      c_sign_priv,
      @sm2.DEFAULT_SM2_ID,
      self.transcript.raw_bytes(),
    ) catch {
      err => {
        self.fail_crypto(@handshake.InternalError, sm2_err_to_msg(err))
        b""
      }
    }
    self.queue_handshake_msg(
      @handshake.CertificateVerify({ signature: sig, }),
      self.outbound,
    )
  }
  // 4. Derive MasterSecret + KeyBlock
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
  // 5. ChangeCipherSpec + switch write cipher + Finished
  self.send_ccs_and_finished(suite, ms, kb)
  self.state = WaitServerChangeCipherSpec
}

///|
fn ClientConn::send_ccs_and_finished(
  self : ClientConn,
  suite : @handshake.CipherSuite,
  ms : Bytes,
  kb : @handshake.KeyBlock,
) -> Unit raise StateError {
  let ccs_wire = self.seal_fragment(@record.ChangeCipherSpec, b"\x01")
  append_bytes(self.outbound, ccs_wire)
  let cipher = make_cipher_state(suite, kb, true)
  self.write_layer.set_cipher(cipher)
  self.write_encrypted = true
  let vd = @handshake.compute_verify_data(ms, true, self.transcript.hash())
  self.queue_handshake_msg(
    @handshake.Finished({ verify_data: vd, }),
    self.outbound,
  )
}

///|
fn ClientConn::handle_handshake_msg(
  self : ClientConn,
  raw_frame : Bytes,
  msg : @handshake.HandshakeMsg,
  events : Array[Event],
) -> Unit raise StateError {
  match (self.state, msg) {
    (WaitServerHello, @handshake.ServerHello(sh)) => {
      if sh.compression_method != b'\x00' {
        self.fail_protocol(
          @handshake.IllegalParameter,
          "unsupported compression method in ServerHello",
        )
      }
      if !self.offered_suite(sh.cipher_suite) {
        self.fail_protocol(
          @handshake.IllegalParameter,
          "server selected unoffered cipher suite",
        )
      }
      self.transcript.update(raw_frame)
      self.server_random = sh.random
      self.session_id = sh.session_id
      self.suite = Some(sh.cipher_suite)
      // Check for Session ID resumption
      match self.config.resume_session {
        Some(rs) =>
          if is_valid_resumed_session(rs) &&
            sh.session_id.length() > 0 &&
            sh.session_id == rs.session_id {
            if sh.cipher_suite != rs.cipher_suite {
              self.fail_protocol(
                @handshake.IllegalParameter,
                "resumed session cipher suite mismatch",
              )
            }
            self.resumed = true
            self.master_secret = rs.master_secret
            self.peer_bundle = rs.peer_certs
            let kb = @handshake.derive_key_block(
              rs.master_secret,
              self.server_random,
              self.client_random,
              sh.cipher_suite,
            )
            self.key_block = Some(kb)
            self.state = WaitServerChangeCipherSpec
            return
          }
        None => ()
      }
      self.state = WaitServerCert
    }
    (WaitServerCert, @handshake.Certificate(cert_msg)) => {
      self.transcript.update(raw_frame)
      let bundle = @x509.parse_and_verify_dual_certs(
        cert_msg.certificates,
        self.config.trust_anchors,
      ) catch {
        err => {
          let (alert, msg_str) = x509_err_to_alert(err)
          self.fail_cert(alert, msg_str)
          abort("unreachable")
        }
      }
      self.peer_bundle = Some(bundle)
      self.state = WaitServerKeyExchange
    }
    (WaitServerKeyExchange, @handshake.ServerKeyExchange(ske)) => {
      self.transcript.update(raw_frame)
      let bundle = match self.peer_bundle {
        Some(b) => b
        None => {
          self.fail_protocol(
            @handshake.InternalError,
            "missing peer certificates",
          )
          return
        }
      }
      match ske {
        @handshake.ServerKeyExchange::Ecc(sig_der) => {
          let tbs = @handshake.build_ecc_ske_tbs(
            self.client_random,
            self.server_random,
            bundle.enc_cert.raw_der,
          )
          if !@sm2.verify_der(
              bundle.sign_cert.public_key,
              @sm2.DEFAULT_SM2_ID,
              tbs,
              sig_der,
            ) {
            self.fail_crypto(
              @handshake.DecryptError,
              "invalid ServerKeyExchange ECC signature",
            )
          }
        }
        @handshake.ServerKeyExchange::Ecdhe(params, sig_der) => {
          let (_, pub_bytes) = @handshake.parse_ecdhe_params(params[:]) catch {
            err => {
              let (alert, msg_str) = handshake_err_to_alert(err)
              self.fail_protocol(alert, msg_str)
              abort("unreachable")
            }
          }
          let eph_pub = @sm2.PublicKey::from_bytes(pub_bytes) catch {
            err => {
              self.fail_crypto(@handshake.IllegalParameter, sm2_err_to_msg(err))
              abort("unreachable")
            }
          }
          let tbs = @handshake.build_ecdhe_ske_tbs(
            self.client_random,
            self.server_random,
            params,
          )
          if !@sm2.verify_der(
              bundle.sign_cert.public_key,
              @sm2.DEFAULT_SM2_ID,
              tbs,
              sig_der,
            ) {
            self.fail_crypto(
              @handshake.DecryptError,
              "invalid ServerKeyExchange ECDHE signature",
            )
          }
          self.server_eph_pub = Some(eph_pub)
        }
      }
      self.state = WaitCertReqOrServerHelloDone
    }
    (WaitCertReqOrServerHelloDone, @handshake.CertificateRequest(_)) => {
      self.transcript.update(raw_frame)
      self.cert_requested = true
      self.state = WaitServerHelloDone
    }
    (WaitCertReqOrServerHelloDone, @handshake.ServerHelloDone) => {
      self.transcript.update(raw_frame)
      self.send_client_flight()
    }
    (WaitServerHelloDone, @handshake.ServerHelloDone) => {
      self.transcript.update(raw_frame)
      self.send_client_flight()
    }
    (WaitServerFinished, @handshake.Finished(fin)) => {
      let expected = @handshake.compute_verify_data(
        self.master_secret,
        false,
        self.transcript.hash(),
      )
      if !@ct.ct_eq(fin.verify_data, expected) {
        self.fail_protocol(
          @handshake.DecryptError,
          "server Finished verify_data mismatch",
        )
      }
      if self.hs_buf.length() != 0 {
        self.fail_protocol(
          @handshake.UnexpectedMessage,
          "trailing handshake bytes after server Finished",
        )
      }
      self.transcript.update(raw_frame)
      if self.resumed {
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
        self.send_ccs_and_finished(suite, self.master_secret, kb)
      }
      self.state = Established
      events.push(HandshakeComplete)
    }
    _ =>
      self.fail_protocol(
        @handshake.UnexpectedMessage,
        "unexpected handshake message for current client state",
      )
  }
}

///|
fn ClientConn::process_handshake_buf(
  self : ClientConn,
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
fn ClientConn::handle_record(
  self : ClientConn,
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
      if self.state == WaitServerChangeCipherSpec ||
        self.state == Established ||
        self.state == Start {
        self.fail_protocol(
          @handshake.UnexpectedMessage,
          "unexpected handshake record in current client state",
        )
      }
      if self.hs_buf.length() + pt.length() >
        @handshake.MAX_HANDSHAKE_MSG_LEN + 4 {
        self.fail_protocol(
          @handshake.DecodeError,
          "handshake reassembly buffer exceeded MAX_HANDSHAKE_MSG_LEN",
        )
      }
      append_bytes(self.hs_buf, pt)
      self.process_handshake_buf(events)
    }
    @record.ChangeCipherSpec => {
      if self.state != WaitServerChangeCipherSpec ||
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
      let cipher = make_cipher_state(suite, kb, false)
      self.read_layer.set_cipher(cipher)
      self.state = WaitServerFinished
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
            "received fatal alert from server",
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
      if self.peer_closed {
        self.fail_protocol(
          @handshake.UnexpectedMessage,
          "application data received after peer CloseNotify",
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
/// coalesced multi-record buffers) into the client state machine.
pub fn ClientConn::feed(
  self : ClientConn,
  data : BytesView,
) -> Array[Event] raise StateError {
  if self.state == Failed {
    raise InvalidState("client connection is in failed state")
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
