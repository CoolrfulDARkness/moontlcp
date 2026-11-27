///|
/// Pure MoonBit, zero-dependency JS ESM / Wasm / Native interactive & TCP bridge
/// API package (`CoolrfulDARkness/moontlcp/web_api`).
///
/// Exports plain `String`/`Bool`/`Int32` -> `String` entry points for:
/// 1. Interactive TLCP 1.1 dual-cert handshake & red-team tamper workbench;
/// 2. Session ID abbreviated resumption bandwidth benchmark;
/// 3. GB/T 38635 SM9 BN256 IBC (KGC, Sign/Verify, PKE, KeyEx) workbench;
/// 4. Stateful OS TCP socket bridge handles for real loopback TLCP 1.1 demos.

// ============================================================================
// Pure-MoonBit Encoding, Hex, UTF-8 & Safe JSON Helpers (Zero External Deps)
// ============================================================================

///|
fn hex_char(nibble : Int32) -> Char {
  let digits = "0123456789abcdef"
  digits[nibble & 0xF].to_int().unsafe_to_char()
}

///|
fn to_hex(data : Bytes) -> String {
  let buf = StringBuilder()
  for i = 0; i < data.length(); i = i + 1 {
    let v = data[i].to_int()
    buf.write_char(hex_char((v >> 4) & 0xF))
    buf.write_char(hex_char(v & 0xF))
  }
  buf.to_string()
}

///|
fn to_hex_preview(data : Bytes, max_bytes : Int32) -> String {
  let limit = if data.length() < max_bytes { data.length() } else { max_bytes }
  let buf = StringBuilder()
  for i = 0; i < limit; i = i + 1 {
    let v = data[i].to_int()
    buf.write_char(hex_char((v >> 4) & 0xF))
    buf.write_char(hex_char(v & 0xF))
  }
  if data.length() > max_bytes {
    buf.write_string("...")
  }
  buf.to_string()
}

///|
fn hex_nibble(c : Int32) -> Int32? {
  if c >= 48 && c <= 57 {
    Some(c - 48)
  } else if c >= 97 && c <= 102 {
    Some(c - 87)
  } else if c >= 65 && c <= 70 {
    Some(c - 55)
  } else {
    None
  }
}

///|
fn from_hex_strict(s : String) -> Bytes? {
  if s.length() % 2 != 0 {
    return None
  }
  let n = s.length() / 2
  let out = FixedArray::make(n, b'\x00')
  for i = 0; i < n; i = i + 1 {
    match (hex_nibble(s[i * 2].to_int()), hex_nibble(s[i * 2 + 1].to_int())) {
      (Some(hi), Some(lo)) => out[i] = ((hi << 4) | lo).to_byte()
      _ => return None
    }
  }
  Some(Bytes::from_array(out))
}

///|
fn utf8_encode(s : String) -> Bytes {
  let out : Array[Byte] = []
  for ch in s {
    let cp = ch.to_int()
    if cp <= 0x7F {
      out.push(cp.to_byte())
    } else if cp <= 0x7FF {
      out.push((0xC0 | ((cp >> 6) & 0x1F)).to_byte())
      out.push((0x80 | (cp & 0x3F)).to_byte())
    } else if cp <= 0xFFFF {
      out.push((0xE0 | ((cp >> 12) & 0x0F)).to_byte())
      out.push((0x80 | ((cp >> 6) & 0x3F)).to_byte())
      out.push((0x80 | (cp & 0x3F)).to_byte())
    } else {
      out.push((0xF0 | ((cp >> 18) & 0x07)).to_byte())
      out.push((0x80 | ((cp >> 12) & 0x3F)).to_byte())
      out.push((0x80 | ((cp >> 6) & 0x3F)).to_byte())
      out.push((0x80 | (cp & 0x3F)).to_byte())
    }
  }
  Bytes::from_array(out)
}

///|
fn utf8_decode(data : Bytes) -> String {
  let buf = StringBuilder()
  let n = data.length()
  let mut i = 0
  while i < n {
    let b0 = data[i].to_int()
    if b0 < 0x80 {
      buf.write_char(b0.unsafe_to_char())
      i = i + 1
    } else if (b0 & 0xE0) == 0xC0 && i + 1 < n {
      let b1 = data[i + 1].to_int()
      if (b1 & 0xC0) == 0x80 {
        let cp = ((b0 & 0x1F) << 6) | (b1 & 0x3F)
        if cp >= 0x80 {
          buf.write_char(cp.unsafe_to_char())
          i = i + 2
          continue
        }
      }
      buf.write_char('\u{FFFD}')
      i = i + 1
    } else if (b0 & 0xF0) == 0xE0 && i + 2 < n {
      let b1 = data[i + 1].to_int()
      let b2 = data[i + 2].to_int()
      if (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 {
        let cp = ((b0 & 0x0F) << 12) | ((b1 & 0x3F) << 6) | (b2 & 0x3F)
        if cp >= 0x800 && (cp < 0xD800 || cp > 0xDFFF) {
          buf.write_char(cp.unsafe_to_char())
          i = i + 3
          continue
        }
      }
      buf.write_char('\u{FFFD}')
      i = i + 1
    } else if (b0 & 0xF8) == 0xF0 && i + 3 < n {
      let b1 = data[i + 1].to_int()
      let b2 = data[i + 2].to_int()
      let b3 = data[i + 3].to_int()
      if (b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80 {
        let cp = ((b0 & 0x07) << 18) |
          ((b1 & 0x3F) << 12) |
          ((b2 & 0x3F) << 6) |
          (b3 & 0x3F)
        if cp >= 0x10000 && cp <= 0x10FFFF {
          buf.write_char(cp.unsafe_to_char())
          i = i + 4
          continue
        }
      }
      buf.write_char('\u{FFFD}')
      i = i + 1
    } else {
      buf.write_char('\u{FFFD}')
      i = i + 1
    }
  }
  buf.to_string()
}

///|
fn json_str(s : String) -> String {
  let buf = StringBuilder()
  buf.write_char('"')
  for ch in s {
    let cp = ch.to_int()
    if ch == '"' {
      buf.write_string("\\\"")
    } else if ch == '\\' {
      buf.write_string("\\\\")
    } else if ch == '\n' {
      buf.write_string("\\n")
    } else if ch == '\r' {
      buf.write_string("\\r")
    } else if ch == '\t' {
      buf.write_string("\\t")
    } else if cp == 8 {
      buf.write_string("\\b")
    } else if cp == 12 {
      buf.write_string("\\f")
    } else if cp < 0x20 {
      buf.write_string("\\u00")
      buf.write_char(hex_char((cp >> 4) & 0xF))
      buf.write_char(hex_char(cp & 0xF))
    } else {
      buf.write_char(ch)
    }
  }
  buf.write_char('"')
  buf.to_string()
}

///|
fn json_bool(b : Bool) -> String {
  if b {
    "true"
  } else {
    "false"
  }
}

///|
fn flip_byte(data : Bytes, idx : Int32, mask : UInt32) -> Bytes {
  if data.length() == 0 || idx < 0 || idx >= data.length() {
    return data
  }
  let out = FixedArray::make(data.length(), b'\x00')
  for i = 0; i < data.length(); i = i + 1 {
    out[i] = data[i]
  }
  out[idx] = (out[idx].to_uint() ^ mask).to_byte()
  Bytes::from_array(out)
}

///|
fn concat_bytes(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for i = 0; i < parts.length(); i = i + 1 {
    total = total + parts[i].length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut off = 0
  for i = 0; i < parts.length(); i = i + 1 {
    let p = parts[i]
    for j = 0; j < p.length(); j = j + 1 {
      out[off + j] = p[j]
    }
    off = off + p.length()
  }
  Bytes::from_array(out)
}

///|
fn collect_app_data(events : Array[@state.Event]) -> Bytes {
  let chunks : Array[Bytes] = []
  for i = 0; i < events.length(); i = i + 1 {
    match events[i] {
      @state.ApplicationData(d) => chunks.push(d)
      _ => ()
    }
  }
  concat_bytes(chunks)
}

///|
fn parse_cipher_suite(name : String) -> @handshake.CipherSuite? {
  match name {
    "ECC_SM4_CBC_SM3" => Some(@handshake.EccSm4CbcSm3)
    "ECC_SM4_GCM_SM3" => Some(@handshake.EccSm4GcmSm3)
    "ECDHE_SM4_CBC_SM3" => Some(@handshake.EcdheSm4CbcSm3)
    "ECDHE_SM4_GCM_SM3" => Some(@handshake.EcdheSm4GcmSm3)
    _ => None
  }
}

///|
fn alert_desc_name(desc : @handshake.AlertDescription) -> String {
  match desc {
    @handshake.CloseNotify => "CloseNotify"
    @handshake.UnexpectedMessage => "UnexpectedMessage"
    @handshake.BadRecordMac => "BadRecordMac"
    @handshake.DecryptionFailed => "DecryptionFailed"
    @handshake.RecordOverflow => "RecordOverflow"
    @handshake.HandshakeFailure => "HandshakeFailure"
    @handshake.BadCertificate => "BadCertificate"
    @handshake.UnsupportedCertificate => "UnsupportedCertificate"
    @handshake.CertificateExpired => "CertificateExpired"
    @handshake.CertificateUnknown => "CertificateUnknown"
    @handshake.IllegalParameter => "IllegalParameter"
    @handshake.UnknownCa => "UnknownCa"
    @handshake.DecodeError => "DecodeError"
    @handshake.DecryptError => "DecryptError"
    @handshake.ProtocolVersion => "ProtocolVersion"
    @handshake.InsufficientSecurity => "InsufficientSecurity"
    @handshake.InternalError => "InternalError"
    @handshake.UnsupportedSite2Site => "UnsupportedSite2Site"
  }
}

///|
fn format_state_error(err : @state.StateError) -> String {
  match err {
    @state.ProtocolError(desc, detail) =>
      "Fatal Alert [" + alert_desc_name(desc) + "]: " + detail
    @state.RecordError(detail) => "RecordError: " + detail
    @state.CertificateError(detail) => "CertificateError: " + detail
    @state.CryptoError(detail) => "CryptoError: " + detail
    @state.InvalidState(detail) => "InvalidState: " + detail
  }
}

///|
fn format_x509_error(err : @x509.X509Error) -> String {
  match err {
    @x509.DerError(m) => "DerError: " + m
    @x509.UnsupportedVersion => "UnsupportedVersion"
    @x509.UnsupportedAlgorithm(m) => "UnsupportedAlgorithm: " + m
    @x509.InvalidPublicKey => "InvalidPublicKey"
    @x509.InvalidSignature => "InvalidSignature"
    @x509.NotCa => "NotCa"
    @x509.BadKeyUsage(m) => "BadKeyUsage: " + m
    @x509.ChainVerificationFailed(m) => "ChainVerificationFailed: " + m
    @x509.DualCertMismatch(m) => "DualCertMismatch: " + m
    @x509.InvalidCertCount(n) => "InvalidCertCount: " + n.to_string()
  }
}

///|
fn format_ku(ku_opt : @x509.KeyUsage?) -> String {
  match ku_opt {
    None => "none"
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
fn format_cert_summary(cert : @x509.Certificate) -> String {
  "CN=" + cert.subject_cn + " | KU=[" + format_ku(cert.key_usage) + "]"
}

///|
fn handshake_type_name(ht : Byte) -> String {
  if ht == @handshake.HT_CLIENT_HELLO {
    "ClientHello"
  } else if ht == @handshake.HT_SERVER_HELLO {
    "ServerHello"
  } else if ht == @handshake.HT_CERTIFICATE {
    "Certificate(Sign+Enc)"
  } else if ht == @handshake.HT_SERVER_KEY_EXCHANGE {
    "ServerKeyExchange"
  } else if ht == @handshake.HT_CERTIFICATE_REQUEST {
    "CertificateRequest"
  } else if ht == @handshake.HT_SERVER_HELLO_DONE {
    "ServerHelloDone"
  } else if ht == @handshake.HT_CERTIFICATE_VERIFY {
    "CertificateVerify"
  } else if ht == @handshake.HT_CLIENT_KEY_EXCHANGE {
    "ClientKeyExchange"
  } else if ht == @handshake.HT_FINISHED {
    "Finished"
  } else {
    "Handshake(0x" + to_hex(Bytes::from_array([ht])) + ")"
  }
}

///|
/// Summarizes TLCP 1.1 wire record contents into a human-readable flight label.
fn summarize_wire_records(wire : Bytes, encrypted_already : Bool) -> String {
  let labels : Array[String] = []
  let mut off = 0
  let mut enc = encrypted_already
  while off < wire.length() {
    let decoded = Some(@record.decode_record(wire[off:])) catch { _ => None }
    match decoded {
      None => {
        labels.push("RawBytes")
        break
      }
      Some((rec, used)) => {
        match rec.content_type {
          @record.ChangeCipherSpec => {
            labels.push("ChangeCipherSpec")
            enc = true
          }
          @record.Alert =>
            if enc {
              labels.push("Encrypted Alert")
            } else {
              let al = try {
                let a = @handshake.decode_alert(rec.payload[:])
                "Fatal Alert(" + alert_desc_name(a.description) + ")"
              } catch {
                _ => "Alert"
              }
              labels.push(al)
            }
          @record.ApplicationData => labels.push("ApplicationData(Encrypted)")
          @record.Handshake =>
            if enc {
              labels.push("Finished(Encrypted)")
            } else {
              let mut hoff = 0
              while hoff < rec.payload.length() {
                let frame = Some(
                  @handshake.decode_handshake_frame(rec.payload[hoff:]),
                ) catch {
                  _ => None
                }
                match frame {
                  Some((ht, _, hused)) => {
                    labels.push(handshake_type_name(ht))
                    hoff = hoff + hused
                  }
                  None => {
                    labels.push("HandshakeFragment")
                    break
                  }
                }
              }
            }
        }
        off = off + used
      }
    }
  }
  let buf = StringBuilder()
  for i = 0; i < labels.length(); i = i + 1 {
    if i > 0 {
      buf.write_string(" + ")
    }
    buf.write_string(labels[i])
  }
  buf.to_string()
}

///|
priv struct FlightRecord {
  dir : String
  label : String
  bytes : Int32
  hex_preview : String
}

///|
fn flights_to_json(flights : Array[FlightRecord]) -> String {
  let buf = StringBuilder()
  buf.write_char('[')
  for i = 0; i < flights.length(); i = i + 1 {
    if i > 0 {
      buf.write_char(',')
    }
    let f = flights[i]
    buf.write_string("{\"dir\":")
    buf.write_string(json_str(f.dir))
    buf.write_string(",\"label\":")
    buf.write_string(json_str(f.label))
    buf.write_string(",\"bytes\":")
    buf.write_string(f.bytes.to_string())
    buf.write_string(",\"hex_preview\":")
    buf.write_string(json_str(f.hex_preview))
    buf.write_char('}')
  }
  buf.write_char(']')
  buf.to_string()
}

///|
fn build_tlcp_json(
  ok : Bool,
  suite : String,
  mutual_auth : Bool,
  tamper_mode : String,
  flights : Array[FlightRecord],
  sign_cert_subject : String,
  enc_cert_subject : String,
  app_ciphertext_hex : String,
  app_plaintext_recovered : String,
  alert_or_error : String,
  total_wire_bytes : Int32,
) -> String {
  let buf = StringBuilder()
  buf.write_string("{\"ok\":")
  buf.write_string(json_bool(ok))
  buf.write_string(",\"suite\":")
  buf.write_string(json_str(suite))
  buf.write_string(",\"mutual_auth\":")
  buf.write_string(json_bool(mutual_auth))
  buf.write_string(",\"tamper_mode\":")
  buf.write_string(json_str(tamper_mode))
  buf.write_string(",\"flights\":")
  buf.write_string(flights_to_json(flights))
  buf.write_string(",\"sign_cert_subject\":")
  buf.write_string(json_str(sign_cert_subject))
  buf.write_string(",\"enc_cert_subject\":")
  buf.write_string(json_str(enc_cert_subject))
  buf.write_string(",\"app_ciphertext_hex\":")
  buf.write_string(json_str(app_ciphertext_hex))
  buf.write_string(",\"app_plaintext_recovered\":")
  buf.write_string(json_str(app_plaintext_recovered))
  buf.write_string(",\"alert_or_error\":")
  buf.write_string(json_str(alert_or_error))
  buf.write_string(",\"total_wire_bytes\":")
  buf.write_string(total_wire_bytes.to_string())
  buf.write_char('}')
  buf.to_string()
}

// ============================================================================
// 1. Interactive TLCP 1.1 Handshake & Red-Team Tamper Workbench API
// ============================================================================

///|
/// Runs a genuine pure-MoonBit GM/T 0024 TLCP 1.1 dual-certificate handshake
/// and encrypted application record exchange (with optional live attack
/// simulation) and returns a JSON report.
///
/// - `suite_name`: `"ECC_SM4_CBC_SM3"`, `"ECC_SM4_GCM_SM3"`,
///   `"ECDHE_SM4_CBC_SM3"`, or `"ECDHE_SM4_GCM_SM3"`.
/// - `mutual_auth`: enables mTLCP client dual-cert auth (ECDHE suites always
///   enforce mTLCP per GB/T 38636).
/// - `tamper_mode`: `"none"`, `"tamper_ciphertext"`, `"swap_dual_certs"`,
///   or `"tamper_finished"`.
/// - `app_message`: UTF-8 application payload encrypted over the TLCP channel.
pub fn run_tlcp_handshake(
  suite_name : String,
  mutual_auth : Bool,
  tamper_mode : String,
  app_message : String,
) -> String {
  let suite = match parse_cipher_suite(suite_name) {
    Some(s) => s
    None =>
      return build_tlcp_json(
        false,
        suite_name,
        mutual_auth,
        tamper_mode,
        [],
        "",
        "",
        "",
        "",
        "Unsupported cipher suite: " + suite_name,
        0,
      )
  }
  if tamper_mode != "none" &&
    tamper_mode != "tamper_ciphertext" &&
    tamper_mode != "swap_dual_certs" &&
    tamper_mode != "tamper_finished" {
    return build_tlcp_json(
      false,
      suite_name,
      mutual_auth,
      tamper_mode,
      [],
      "",
      "",
      "",
      "",
      "Unsupported tamper_mode: " + tamper_mode,
      0,
    )
  }
  let effective_mutual = mutual_auth || suite.is_ecdhe()
  let pki = @lib.generate_test_pki(b"moontlcp-web-pki-v1") catch {
    err =>
      return build_tlcp_json(
        false,
        suite.name(),
        effective_mutual,
        tamper_mode,
        [],
        "",
        "",
        "",
        "",
        "PKI init failed: " + format_x509_error(err),
        0,
      )
  }
  let swap_certs = tamper_mode == "swap_dual_certs"
  let server_sign_cert = if swap_certs {
    pki.server_enc_cert
  } else {
    pki.server_sign_cert
  }
  let server_sign_priv = if swap_certs {
    pki.server_enc_priv
  } else {
    pki.server_sign_priv
  }
  let server_enc_cert = if swap_certs {
    pki.server_sign_cert
  } else {
    pki.server_enc_cert
  }
  let server_enc_priv = if swap_certs {
    pki.server_sign_priv
  } else {
    pki.server_enc_priv
  }
  let sign_subj = format_cert_summary(server_sign_cert)
  let enc_subj = format_cert_summary(server_enc_cert)
  let client = @lib.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [suite],
    client_certs: if effective_mutual {
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
    seed: b"moontlcp-web-client-seed",
  })
  let server = @lib.new_server({
    sign_cert: server_sign_cert,
    sign_priv: server_sign_priv,
    enc_cert: server_enc_cert,
    enc_priv: server_enc_priv,
    cipher_suites: [suite],
    require_client_cert: effective_mutual,
    client_trust_anchors: [pki.ca_cert],
    session_store: None,
    seed: b"moontlcp-web-server-seed",
  })
  let flights : Array[FlightRecord] = []
  let mut total_bytes = 0
  // Flight 1: ClientHello (C -> S)
  let ch_wire = client.start_handshake() catch {
    err =>
      return build_tlcp_json(
        false,
        suite.name(),
        effective_mutual,
        tamper_mode,
        flights,
        sign_subj,
        enc_subj,
        "",
        "",
        format_state_error(err),
        total_bytes,
      )
  }
  total_bytes = total_bytes + ch_wire.length()
  flights.push({
    dir: "C -> S",
    label: summarize_wire_records(ch_wire, false),
    bytes: ch_wire.length(),
    hex_preview: to_hex_preview(ch_wire, 64),
  })
  let _ = server.feed(ch_wire[:]) catch {
    err => {
      let alert_w = server.take_outbound()
      if alert_w.length() > 0 {
        total_bytes = total_bytes + alert_w.length()
        flights.push({
          dir: "S -> C",
          label: summarize_wire_records(alert_w, false),
          bytes: alert_w.length(),
          hex_preview: to_hex_preview(alert_w, 64),
        })
      }
      return build_tlcp_json(
        false,
        suite.name(),
        effective_mutual,
        tamper_mode,
        flights,
        sign_subj,
        enc_subj,
        "",
        "",
        format_state_error(err),
        total_bytes,
      )
    }
  }
  // Flight 2: ServerHello + Certificate(Sign+Enc) + ServerKeyExchange + [CertReq] + ServerHelloDone (S -> C)
  let s_flight2 = server.take_outbound()
  total_bytes = total_bytes + s_flight2.length()
  let f2_label = if swap_certs {
    summarize_wire_records(s_flight2, false) + " [SWAPPED: Enc before Sign]"
  } else {
    summarize_wire_records(s_flight2, false)
  }
  flights.push({
    dir: "S -> C",
    label: f2_label,
    bytes: s_flight2.length(),
    hex_preview: to_hex_preview(s_flight2, 64),
  })
  let _ = client.feed(s_flight2[:]) catch {
    err => {
      let alert_w = client.take_outbound()
      if alert_w.length() > 0 {
        total_bytes = total_bytes + alert_w.length()
        flights.push({
          dir: "C -> S",
          label: summarize_wire_records(alert_w, false),
          bytes: alert_w.length(),
          hex_preview: to_hex_preview(alert_w, 64),
        })
      }
      return build_tlcp_json(
        false,
        suite.name(),
        effective_mutual,
        tamper_mode,
        flights,
        sign_subj,
        enc_subj,
        "",
        "",
        format_state_error(err),
        total_bytes,
      )
    }
  }
  // Flight 3: [ClientCert] + ClientKeyExchange + [CertVerify] + CCS + Encrypted Finished (C -> S)
  let c_flight3_raw = client.take_outbound()
  let c_flight3 = if tamper_mode == "tamper_finished" {
    flip_byte(c_flight3_raw, c_flight3_raw.length() - 1, 0x01U)
  } else {
    c_flight3_raw
  }
  total_bytes = total_bytes + c_flight3.length()
  let f3_label = if tamper_mode == "tamper_finished" {
    summarize_wire_records(c_flight3, false) + " [TAMPERED 1-bit]"
  } else {
    summarize_wire_records(c_flight3, false)
  }
  flights.push({
    dir: "C -> S",
    label: f3_label,
    bytes: c_flight3.length(),
    hex_preview: to_hex_preview(c_flight3, 64),
  })
  let _ = server.feed(c_flight3[:]) catch {
    err => {
      let alert_w = server.take_outbound()
      if alert_w.length() > 0 {
        total_bytes = total_bytes + alert_w.length()
        flights.push({
          dir: "S -> C",
          label: "Fatal Alert (Server Rejected Finished)",
          bytes: alert_w.length(),
          hex_preview: to_hex_preview(alert_w, 64),
        })
      }
      return build_tlcp_json(
        false,
        suite.name(),
        effective_mutual,
        tamper_mode,
        flights,
        sign_subj,
        enc_subj,
        "",
        "",
        format_state_error(err),
        total_bytes,
      )
    }
  }
  // Flight 4: Server CCS + Encrypted Finished (S -> C)
  let s_flight4 = server.take_outbound()
  total_bytes = total_bytes + s_flight4.length()
  flights.push({
    dir: "S -> C",
    label: summarize_wire_records(s_flight4, false),
    bytes: s_flight4.length(),
    hex_preview: to_hex_preview(s_flight4, 64),
  })
  let _ = client.feed(s_flight4[:]) catch {
    err =>
      return build_tlcp_json(
        false,
        suite.name(),
        effective_mutual,
        tamper_mode,
        flights,
        sign_subj,
        enc_subj,
        "",
        "",
        format_state_error(err),
        total_bytes,
      )
  }
  // Flight 5: Encrypted ApplicationData (C -> S)
  let payload_text = if app_message.length() == 0 {
    "Hello GM/T 0024 TLCP 1.1!"
  } else {
    app_message
  }
  let payload_bytes = utf8_encode(payload_text)
  let app_wire_raw = client.write_app_data(payload_bytes) catch {
    err =>
      return build_tlcp_json(
        false,
        suite.name(),
        effective_mutual,
        tamper_mode,
        flights,
        sign_subj,
        enc_subj,
        "",
        "",
        format_state_error(err),
        total_bytes,
      )
  }
  let app_wire = if tamper_mode == "tamper_ciphertext" {
    flip_byte(app_wire_raw, app_wire_raw.length() - 1, 0x01U)
  } else {
    app_wire_raw
  }
  total_bytes = total_bytes + app_wire.length()
  flights.push({
    dir: "C -> S",
    label: if tamper_mode == "tamper_ciphertext" {
      "ApplicationData(Encrypted) [TAMPERED 1-bit]"
    } else {
      "ApplicationData(Encrypted)"
    },
    bytes: app_wire.length(),
    hex_preview: to_hex_preview(app_wire, 64),
  })
  let events = server.feed(app_wire[:]) catch {
    err => {
      let alert_w = server.take_outbound()
      if alert_w.length() > 0 {
        total_bytes = total_bytes + alert_w.length()
        flights.push({
          dir: "S -> C",
          label: "Fatal Alert (Encrypted BadRecordMac)",
          bytes: alert_w.length(),
          hex_preview: to_hex_preview(alert_w, 64),
        })
      }
      return build_tlcp_json(
        false,
        suite.name(),
        effective_mutual,
        tamper_mode,
        flights,
        sign_subj,
        enc_subj,
        to_hex(app_wire),
        "",
        format_state_error(err),
        total_bytes,
      )
    }
  }
  let recovered = utf8_decode(collect_app_data(events))
  let ok = client.is_established() &&
    server.is_established() &&
    recovered == payload_text
  build_tlcp_json(
    ok,
    suite.name(),
    effective_mutual,
    tamper_mode,
    flights,
    sign_subj,
    enc_subj,
    to_hex(app_wire),
    recovered,
    "",
    total_bytes,
  )
}

// ============================================================================
// 2. TLCP Session ID Abbreviated Resumption Bandwidth Benchmark API
// ============================================================================

///|
/// Runs a real full TLCP 1.1 handshake followed by a Session ID abbreviated
/// resumption handshake on the same server `SessionStore`, returning JSON with
/// exact wire bytes, bandwidth savings percentage, and session ID.
pub fn run_tlcp_session_resume(suite_name : String) -> String {
  fn err_json(msg : String) -> String {
    let buf = StringBuilder()
    buf.write_string("{\"ok\":false,\"suite\":")
    buf.write_string(json_str(suite_name))
    buf.write_string(
      ",\"full_wire_bytes\":0,\"resumed_wire_bytes\":0,\"savings_percent\":0,\"session_id_hex\":\"\",\"resumed_ok\":false,\"alert_or_error\":",
    )
    buf.write_string(json_str(msg))
    buf.write_char('}')
    buf.to_string()
  }

  let suite = match parse_cipher_suite(suite_name) {
    Some(s) => s
    None => return err_json("Unsupported cipher suite: " + suite_name)
  }
  let pki = @lib.generate_test_pki(b"moontlcp-web-resume-pki") catch {
    err => return err_json("PKI init failed: " + format_x509_error(err))
  }
  let store = @lib.new_session_store()
  let need_client = suite.is_ecdhe()
  let c1_certs = if need_client {
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
  }
  let c1 = @lib.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [suite],
    client_certs: c1_certs,
    resume_session: None,
    seed: b"moontlcp-web-res-c1",
  })
  let s1 = @lib.new_server({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [suite],
    require_client_cert: need_client,
    client_trust_anchors: [pki.ca_cert],
    session_store: Some(store),
    seed: b"moontlcp-web-res-s1",
  })
  let (fc, fs) = @lib.run_handshake_loop(c1, s1) catch {
    err => return err_json("Full handshake failed: " + format_state_error(err))
  }
  let full_total = fc + fs
  let saved = c1.export_session()
  let sid_hex = to_hex(c1.session_id())
  let c2 = @lib.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [suite],
    client_certs: c1_certs,
    resume_session: saved,
    seed: b"moontlcp-web-res-c2",
  })
  let s2 = @lib.new_server({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [suite],
    require_client_cert: need_client,
    client_trust_anchors: [pki.ca_cert],
    session_store: Some(store),
    seed: b"moontlcp-web-res-s2",
  })
  let (rc, rs) = @lib.run_handshake_loop(c2, s2) catch {
    err =>
      return err_json("Resumed handshake failed: " + format_state_error(err))
  }
  let res_total = rc + rs
  let test_msg = b"resumed-session-verify"
  let wire = c2.write_app_data(test_msg) catch {
    err => return err_json("Resumed write failed: " + format_state_error(err))
  }
  let events = s2.feed(wire[:]) catch {
    err => return err_json("Resumed read failed: " + format_state_error(err))
  }
  let resumed_ok = c2.is_resumed() &&
    s2.is_resumed() &&
    collect_app_data(events) == test_msg
  let savings_pct = if full_total > 0 {
    (full_total - res_total) * 100 / full_total
  } else {
    0
  }
  let buf = StringBuilder()
  buf.write_string("{\"ok\":")
  buf.write_string(json_bool(resumed_ok))
  buf.write_string(",\"suite\":")
  buf.write_string(json_str(suite.name()))
  buf.write_string(",\"full_wire_bytes\":")
  buf.write_string(full_total.to_string())
  buf.write_string(",\"resumed_wire_bytes\":")
  buf.write_string(res_total.to_string())
  buf.write_string(",\"full_client_bytes\":")
  buf.write_string(fc.to_string())
  buf.write_string(",\"full_server_bytes\":")
  buf.write_string(fs.to_string())
  buf.write_string(",\"resumed_client_bytes\":")
  buf.write_string(rc.to_string())
  buf.write_string(",\"resumed_server_bytes\":")
  buf.write_string(rs.to_string())
  buf.write_string(",\"savings_percent\":")
  buf.write_string(savings_pct.to_string())
  buf.write_string(",\"session_id_hex\":")
  buf.write_string(json_str(sid_hex))
  buf.write_string(",\"resumed_ok\":")
  buf.write_string(json_bool(resumed_ok))
  buf.write_string(",\"alert_or_error\":\"\"}")
  buf.to_string()
}

// ============================================================================
// 3. GB/T 38635 SM9 BN256 IBC Interactive Workbench API
// ============================================================================

///|
fn parse_sm9_enc_mode(mode_name : String) -> (@sm9_enc.EncMode, String)? {
  match mode_name {
    "kdf_xor" | "KdfXor" | "KDF-XOR" =>
      Some((@sm9_enc.EncMode::KdfXor, "kdf_xor"))
    "sm4_ecb" | "Sm4EcbPkcs7" | "SM4-ECB" =>
      Some((@sm9_enc.EncMode::Sm4EcbPkcs7, "sm4_ecb"))
    _ => None
  }
}

///|
fn tamper_sm9_signature(sig : @sm9_sign.Signature) -> @sm9_sign.Signature {
  let raw = sig.to_bytes_raw()
  let flipped1 = flip_byte(raw, 31, 0x01U)
  match @sm9_sign.Signature::from_bytes_raw_strict(flipped1[:]) {
    Some(s) => s
    None => {
      let flipped2 = flip_byte(raw, 31, 0x02U)
      match @sm9_sign.Signature::from_bytes_raw_strict(flipped2[:]) {
        Some(s) => s
        None => sig
      }
    }
  }
}

///|
/// Runs real GB/T 38635-2020 SM9 BN256 identity-based cryptography over the
/// shared `crypto/sm3` + `crypto/sm4` core:
/// - KGC master keys & user private keys (`sign`, `enc`, `keyex`);
/// - SM9 Part 2 digital signature & verification (with optional 1-bit tamper);
/// - SM9 Part 4 PKE encrypt & decrypt (`"kdf_xor"` or `"sm4_ecb"`);
/// - SM9 Part 3 Key Exchange with mutual key confirmation (`S_B==S_1`, `S_A==S_2`).
pub fn run_sm9_demo(
  signer_id : String,
  recipient_id : String,
  message : String,
  enc_mode : String,
  tamper_sig : Bool,
) -> String {
  fn build_sm9_json(
    ok : Bool,
    mode_label : String,
    sig_h_hex : String,
    sig_valid : Bool,
    tamper_blocked : Bool,
    ciphertext_hex : String,
    decrypted_message : String,
    keyex_confirmed : Bool,
    shared_key_hex : String,
    error_msg : String,
  ) -> String {
    let buf = StringBuilder()
    buf.write_string("{\"ok\":")
    buf.write_string(json_bool(ok))
    buf.write_string(",\"signer_id\":")
    buf.write_string(json_str(signer_id))
    buf.write_string(",\"recipient_id\":")
    buf.write_string(json_str(recipient_id))
    buf.write_string(",\"enc_mode\":")
    buf.write_string(json_str(mode_label))
    buf.write_string(",\"sig_h_hex\":")
    buf.write_string(json_str(sig_h_hex))
    buf.write_string(",\"sig_valid\":")
    buf.write_string(json_bool(sig_valid))
    buf.write_string(",\"tamper_blocked\":")
    buf.write_string(json_bool(tamper_blocked))
    buf.write_string(",\"ciphertext_hex\":")
    buf.write_string(json_str(ciphertext_hex))
    buf.write_string(",\"decrypted_message\":")
    buf.write_string(json_str(decrypted_message))
    buf.write_string(",\"keyex_confirmed\":")
    buf.write_string(json_bool(keyex_confirmed))
    buf.write_string(",\"shared_key_hex\":")
    buf.write_string(json_str(shared_key_hex))
    buf.write_string(",\"error\":")
    buf.write_string(json_str(error_msg))
    buf.write_char('}')
    buf.to_string()
  }

  let (mode, mode_label) = match parse_sm9_enc_mode(enc_mode) {
    Some(pair) => pair
    None =>
      return build_sm9_json(
        false,
        enc_mode,
        "",
        false,
        false,
        "",
        "",
        false,
        "",
        "Unsupported enc_mode: " + enc_mode + " (use kdf_xor or sm4_ecb)",
      )
  }
  if signer_id.length() == 0 || recipient_id.length() == 0 {
    return build_sm9_json(
      false, mode_label, "", false, false, "", "", false, "", "signer_id and recipient_id must be non-empty",
    )
  }
  let id_a = utf8_encode(signer_id)
  let id_b = utf8_encode(recipient_id)
  let msg_text = if message.length() == 0 {
    "GB/T 38635 SM9 BN256 IBC"
  } else {
    message
  }
  let msg_bytes = utf8_encode(msg_text)
  // 1. KGC master key generation & user private key extraction
  let sign_master = @sm9.sign_master_from_seed(b"moontlcp-web-sm9-sign-kgc")
  let p_pub_s = sign_master.public_key()
  let enc_master = @sm9.enc_master_from_seed(b"moontlcp-web-sm9-enc-kgc")
  let p_pub_e = enc_master.public_key()
  let ds_a = match @sm9.extract_sign_key(sign_master, id_a) {
    Ok(k) => k
    Err(e) =>
      return build_sm9_json(
        false, mode_label, "", false, false, "", "", false, "", e,
      )
  }
  let de_b_enc = match @sm9.extract_enc_key(enc_master, id_b) {
    Ok(k) => k
    Err(e) =>
      return build_sm9_json(
        false, mode_label, "", false, false, "", "", false, "", e,
      )
  }
  let de_a_kx = match @sm9.extract_keyex_key(enc_master, id_a) {
    Ok(k) => k
    Err(e) =>
      return build_sm9_json(
        false, mode_label, "", false, false, "", "", false, "", e,
      )
  }
  let de_b_kx = match @sm9.extract_keyex_key(enc_master, id_b) {
    Ok(k) => k
    Err(e) =>
      return build_sm9_json(
        false, mode_label, "", false, false, "", "", false, "", e,
      )
  }
  // 2. SM9 Digital Signature & Verification (+ optional 1-bit tamper)
  let orig_sig = match
    @sm9.sign(p_pub_s, ds_a, msg_bytes, entropy=b"moontlcp-web-sm9-sign-ent") {
    Ok(s) => s
    Err(e) =>
      return build_sm9_json(
        false, mode_label, "", false, false, "", "", false, "", e,
      )
  }
  let checked_sig = if tamper_sig {
    tamper_sm9_signature(orig_sig)
  } else {
    orig_sig
  }
  let sig_h_hex = to_hex(checked_sig.h().to_be_bytes())
  let sig_valid = @sm9.verify(p_pub_s, id_a, msg_bytes, checked_sig)
  let tamper_blocked = tamper_sig && !sig_valid
  // 3. SM9 PKE Encrypt & Decrypt (KDF-XOR or SM4-ECB-PKCS#7 via shared crypto/sm4)
  let pke_entropy = @lib.sm3_hash(
    concat_bytes([b"moontlcp-web-sm9-pke|", id_b, b"|", msg_bytes]),
  )
  let ct = match @sm9.encrypt(p_pub_e, id_b, msg_bytes, pke_entropy, mode~) {
    Ok(c) => c
    Err(e) =>
      return build_sm9_json(
        false, mode_label, sig_h_hex, sig_valid, tamper_blocked, "", "", false, "",
        e,
      )
  }
  let dec_bytes = match @sm9.decrypt(id_b, de_b_enc, ct, mode~) {
    Ok(pt) => pt
    Err(e) =>
      return build_sm9_json(
        false,
        mode_label,
        sig_h_hex,
        sig_valid,
        tamper_blocked,
        to_hex(ct),
        "",
        false,
        "",
        e,
      )
  }
  let decrypted_message = utf8_decode(dec_bytes)
  let pke_ok = decrypted_message == msg_text
  // 4. SM9 Key Exchange with Mutual Key Confirmation (S_B == S_1, S_A == S_2)
  let r_a = @sm9_field.Fn::from_u64(0x2026112812345679UL)
  let r_b = @sm9_field.Fn::from_u64(0x2026112898765433UL)
  let (keyex_confirmed, shared_key_hex, kx_err) = match
    (
      @sm9.keyex_ephemeral(p_pub_e, id_b, r_a),
      @sm9.keyex_ephemeral(p_pub_e, id_a, r_b),
    ) {
    (Ok(ra_pt), Ok(rb_pt)) =>
      match
        @sm9.keyex_responder(
          p_pub_e, id_a, id_b, de_b_kx, r_b, ra_pt, rb_pt, 32,
        ) {
        Ok(resp) =>
          match
            @sm9.keyex_initiator(
              p_pub_e,
              id_a,
              id_b,
              de_a_kx,
              r_a,
              ra_pt,
              rb_pt,
              32,
              peer_s_b=resp.s_b,
            ) {
            Ok(init) => {
              let confirmed = resp.sk == init.sk &&
                @sm9.keyex_verify_confirmation(resp.s_2, init.s_a)
              (confirmed, to_hex(init.sk), "")
            }
            Err(e) => (false, "", e)
          }
        Err(e) => (false, "", e)
      }
    (Err(e), _) => (false, "", e)
    (_, Err(e)) => (false, "", e)
  }
  let ok = sig_valid && pke_ok && keyex_confirmed && kx_err.length() == 0
  let err_msg = if kx_err.length() > 0 {
    kx_err
  } else if tamper_blocked {
    "SM9 signature verification rejected 1-bit tampered signature"
  } else {
    ""
  }
  build_sm9_json(
    ok,
    mode_label,
    sig_h_hex,
    sig_valid,
    tamper_blocked,
    to_hex(ct),
    decrypted_message,
    keyex_confirmed,
    shared_key_hex,
    err_msg,
  )
}

// ============================================================================
// 4. Stateful OS TCP Socket Bridge APIs (Managed Integer Handles)
// ============================================================================

///|
priv enum TcpPeer {
  Client(@state.ClientConn)
  Server(@state.ServerConn)
}

///|
priv struct TcpSlot {
  peer : TcpPeer
  out_buf : Array[Byte]
}

///|
let tcp_slots : Array[TcpSlot?] = []

///|
let tcp_pair_counter : Ref[Int32] = { val: 0, }

///|
fn append_bytes_to_buf(buf : Array[Byte], data : Bytes) -> Unit {
  for i = 0; i < data.length(); i = i + 1 {
    buf.push(data[i])
  }
}

///|
fn drain_buf(buf : Array[Byte]) -> Bytes {
  if buf.length() == 0 {
    return b""
  }
  let out = FixedArray::make(buf.length(), b'\x00')
  for i = 0; i < buf.length(); i = i + 1 {
    out[i] = buf[i]
  }
  buf.clear()
  Bytes::from_array(out)
}

///|
fn alloc_tcp_slot(slot : TcpSlot) -> Int32 {
  for i = 0; i < tcp_slots.length(); i = i + 1 {
    if tcp_slots[i] is None {
      tcp_slots[i] = Some(slot)
      return i + 1
    }
  }
  tcp_slots.push(Some(slot))
  tcp_slots.length()
}

///|
fn get_tcp_slot(handle : Int32) -> TcpSlot? {
  if handle <= 0 || handle > tcp_slots.length() {
    return None
  }
  tcp_slots[handle - 1]
}

///|
fn peer_state_label(peer : TcpPeer) -> String {
  match peer {
    Client(c) =>
      if c.is_established() {
        "ESTABLISHED"
      } else if c.is_failed() {
        "FAILED"
      } else {
        "HANDSHAKING"
      }
    Server(s) =>
      if s.is_established() {
        "ESTABLISHED"
      } else if s.is_failed() {
        "FAILED"
      } else {
        "HANDSHAKING"
      }
  }
}

///|
fn flush_peer_outbound(slot : TcpSlot) -> Unit {
  let out = match slot.peer {
    Client(c) => c.take_outbound()
    Server(s) => s.take_outbound()
  }
  if out.length() > 0 {
    append_bytes_to_buf(slot.out_buf, out)
  }
}

///|
/// Creates a real TLCP 1.1 client + server pair with fresh SM2 CA & dual certs,
/// initiates the client handshake, and returns `"OK:<client_id>|<server_id>"`.
pub fn tlcp_tcp_init_pair(suite_name : String, mutual_auth : Bool) -> String {
  let suite = match parse_cipher_suite(suite_name) {
    Some(s) => s
    None => return "ERR:unsupported cipher suite: " + suite_name
  }
  tcp_pair_counter.val = tcp_pair_counter.val + 1
  let tag = utf8_encode("moontlcp-tcp-pair-" + tcp_pair_counter.val.to_string())
  let pki = @lib.generate_test_pki(tag) catch {
    err => return "ERR:PKI generation failed: " + format_x509_error(err)
  }
  let effective_mutual = mutual_auth || suite.is_ecdhe()
  let client = @lib.new_client({
    trust_anchors: [pki.ca_cert],
    cipher_suites: [suite],
    client_certs: if effective_mutual {
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
    seed: concat_bytes([b"tcp-c-", tag]),
  })
  let server = @lib.new_server({
    sign_cert: pki.server_sign_cert,
    sign_priv: pki.server_sign_priv,
    enc_cert: pki.server_enc_cert,
    enc_priv: pki.server_enc_priv,
    cipher_suites: [suite],
    require_client_cert: effective_mutual,
    client_trust_anchors: [pki.ca_cert],
    session_store: None,
    seed: concat_bytes([b"tcp-s-", tag]),
  })
  let ch = client.start_handshake() catch {
    err => return "ERR:" + format_state_error(err)
  }
  let client_slot : TcpSlot = { peer: Client(client), out_buf: [], }
  append_bytes_to_buf(client_slot.out_buf, ch)
  let server_slot : TcpSlot = { peer: Server(server), out_buf: [], }
  let client_id = alloc_tcp_slot(client_slot)
  let server_id = alloc_tcp_slot(server_slot)
  "OK:" + client_id.to_string() + "|" + server_id.to_string()
}

///|
/// Drains pending outbound GM/T 0024 wire bytes queued for TCP transmission.
/// Returns `"OK:<hex>"` (or `"OK:"` if empty) or `"ERR:<msg>"`.
pub fn tlcp_tcp_poll_out(handle : Int32) -> String {
  match get_tcp_slot(handle) {
    None => "ERR:invalid handle " + handle.to_string()
    Some(slot) => {
      flush_peer_outbound(slot)
      let bytes = drain_buf(slot.out_buf)
      "OK:" + to_hex(bytes)
    }
  }
}

///|
/// Feeds hex-encoded raw TCP wire bytes into the TLCP 1.1 client/server state
/// machine. Returns `"OK:<state>|<decrypted_app_hex>"` or `"ERR:<msg>"`.
pub fn tlcp_tcp_feed_in(handle : Int32, hex_bytes : String) -> String {
  let slot = match get_tcp_slot(handle) {
    None => return "ERR:invalid handle " + handle.to_string()
    Some(s) => s
  }
  let raw = match from_hex_strict(hex_bytes) {
    None => return "ERR:invalid hex input"
    Some(b) => b
  }
  let events = match slot.peer {
    Client(c) =>
      c.feed(raw[:]) catch {
        err => {
          flush_peer_outbound(slot)
          return "ERR:" + format_state_error(err)
        }
      }
    Server(s) =>
      s.feed(raw[:]) catch {
        err => {
          flush_peer_outbound(slot)
          return "ERR:" + format_state_error(err)
        }
      }
  }
  flush_peer_outbound(slot)
  let app = collect_app_data(events)
  "OK:" + peer_state_label(slot.peer) + "|" + to_hex(app)
}

///|
/// Encrypts a UTF-8 plaintext string as TLCP 1.1 ApplicationData record(s) and
/// queues the wire bytes on `handle` for `tlcp_tcp_poll_out`.
pub fn tlcp_tcp_send_app(handle : Int32, plaintext : String) -> String {
  let slot = match get_tcp_slot(handle) {
    None => return "ERR:invalid handle " + handle.to_string()
    Some(s) => s
  }
  let payload = utf8_encode(plaintext)
  let wire = match slot.peer {
    Client(c) =>
      c.write_app_data(payload) catch {
        err => return "ERR:" + format_state_error(err)
      }
    Server(s) =>
      s.write_app_data(payload) catch {
        err => return "ERR:" + format_state_error(err)
      }
  }
  append_bytes_to_buf(slot.out_buf, wire)
  "OK"
}

///|
/// Releases a managed TCP bridge handle.
pub fn tlcp_tcp_close(handle : Int32) -> String {
  if handle <= 0 || handle > tcp_slots.length() {
    return "ERR:invalid handle " + handle.to_string()
  }
  match tcp_slots[handle - 1] {
    None => "ERR:handle already closed"
    Some(_) => {
      tcp_slots[handle - 1] = None
      "OK"
    }
  }
}
