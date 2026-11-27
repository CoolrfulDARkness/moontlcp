///|
/// Stateless, read-only GM/T 0024-2023 (TLCP 1.1) handshake & alert dissector APIs.
///
/// Designed for zero-coupling packet analyzers (e.g. `moonshark`) to inspect
/// plaintext TLCP handshake messages and alerts without running a session state machine.

///|
/// Read-only structural summary of a single plaintext TLCP handshake message.
#derive(Debug, Eq)
pub(all) struct HandshakeSummary {
  msg_type : Byte
  msg_type_name : String
  body_len : Int32
  total_wire_len : Int32
  protocol_version : UInt32
  cipher_suites : Array[UInt32]
  selected_suite : UInt32?
  cert_count : Int32
  session_id_len : Int32
}

///|
/// Returns the human-readable GM/T 0024-2023 name for an `AlertDescription`.
pub fn AlertDescription::name(self : AlertDescription) -> String {
  match self {
    CloseNotify => "CloseNotify"
    UnexpectedMessage => "UnexpectedMessage"
    BadRecordMac => "BadRecordMac"
    DecryptionFailed => "DecryptionFailed"
    RecordOverflow => "RecordOverflow"
    HandshakeFailure => "HandshakeFailure"
    BadCertificate => "BadCertificate"
    UnsupportedCertificate => "UnsupportedCertificate"
    CertificateExpired => "CertificateExpired"
    CertificateUnknown => "CertificateUnknown"
    IllegalParameter => "IllegalParameter"
    UnknownCa => "UnknownCa"
    AlertDescription::DecodeError => "DecodeError"
    DecryptError => "DecryptError"
    ProtocolVersion => "ProtocolVersion"
    InsufficientSecurity => "InsufficientSecurity"
    InternalError => "InternalError"
    UnsupportedSite2Site => "UnsupportedSite2Site"
  }
}

///|
fn validate_inspect_extensions(
  body : BytesView,
  pos : Int32,
) -> Unit raise HandshakeError {
  if pos == body.length() {
    return
  }
  if pos + 2 > body.length() {
    raise InvalidLength
  }
  let ext_len = read_be16(body, pos)
  let mut p = pos + 2
  if p + ext_len != body.length() {
    raise InvalidLength
  }
  while p < body.length() {
    if p + 4 > body.length() {
      raise InvalidLength
    }
    let item_len = read_be16(body, p + 2)
    p = p + 4
    if p + item_len > body.length() {
      raise InvalidLength
    }
    p = p + item_len
  }
}

///|
fn inspect_client_hello_body(
  body : BytesView,
  total_wire_len : Int32,
) -> HandshakeSummary raise HandshakeError {
  if body.length() < 2 + RANDOM_LEN + 1 {
    raise InvalidLength
  }
  let protocol_version = read_be16(body, 0).reinterpret_as_uint()
  let mut pos = 2 + RANDOM_LEN
  let sid_len = body[pos].to_int()
  pos = pos + 1
  if sid_len > MAX_SESSION_ID_LEN || pos + sid_len > body.length() {
    raise InvalidLength
  }
  pos = pos + sid_len
  if pos + 2 > body.length() {
    raise InvalidLength
  }
  let cs_bytes = read_be16(body, pos)
  pos = pos + 2
  if cs_bytes < 2 || cs_bytes % 2 != 0 || pos + cs_bytes > body.length() {
    raise InvalidLength
  }
  let cipher_suites : Array[UInt32] = Array(capacity=cs_bytes / 2)
  let cs_end = pos + cs_bytes
  while pos < cs_end {
    cipher_suites.push(read_be16(body, pos).reinterpret_as_uint())
    pos = pos + 2
  }
  if pos + 1 > body.length() {
    raise InvalidLength
  }
  let cm_len = body[pos].to_int()
  pos = pos + 1
  if cm_len < 1 || pos + cm_len > body.length() {
    raise InvalidLength
  }
  pos = pos + cm_len
  validate_inspect_extensions(body, pos)
  {
    msg_type: HT_CLIENT_HELLO,
    msg_type_name: "ClientHello",
    body_len: body.length(),
    total_wire_len,
    protocol_version,
    cipher_suites,
    selected_suite: None,
    cert_count: 0,
    session_id_len: sid_len,
  }
}

///|
fn inspect_server_hello_body(
  body : BytesView,
  total_wire_len : Int32,
) -> HandshakeSummary raise HandshakeError {
  if body.length() < 2 + RANDOM_LEN + 1 {
    raise InvalidLength
  }
  let protocol_version = read_be16(body, 0).reinterpret_as_uint()
  let mut pos = 2 + RANDOM_LEN
  let sid_len = body[pos].to_int()
  pos = pos + 1
  if sid_len > MAX_SESSION_ID_LEN || pos + sid_len + 3 > body.length() {
    raise InvalidLength
  }
  pos = pos + sid_len
  let suite = read_be16(body, pos).reinterpret_as_uint()
  pos = pos + 3
  validate_inspect_extensions(body, pos)
  {
    msg_type: HT_SERVER_HELLO,
    msg_type_name: "ServerHello",
    body_len: body.length(),
    total_wire_len,
    protocol_version,
    cipher_suites: [],
    selected_suite: Some(suite),
    cert_count: 0,
    session_id_len: sid_len,
  }
}

///|
fn inspect_certificate_body(
  body : BytesView,
  total_wire_len : Int32,
) -> HandshakeSummary raise HandshakeError {
  if body.length() < 3 {
    raise InvalidLength
  }
  let total_len = read_be24(body, 0)
  if 3 + total_len != body.length() {
    raise InvalidLength
  }
  let mut cert_count = 0
  let mut pos = 3
  while pos < body.length() {
    if pos + 3 > body.length() {
      raise InvalidLength
    }
    let cert_len = read_be24(body, pos)
    pos = pos + 3
    if cert_len == 0 || pos + cert_len > body.length() {
      raise InvalidLength
    }
    cert_count = cert_count + 1
    pos = pos + cert_len
  }
  {
    msg_type: HT_CERTIFICATE,
    msg_type_name: "Certificate",
    body_len: body.length(),
    total_wire_len,
    protocol_version: 0U,
    cipher_suites: [],
    selected_suite: None,
    cert_count,
    session_id_len: 0,
  }
}

///|
fn validate_ske_body(body : BytesView) -> Unit raise HandshakeError {
  let ecc_ok = if body.length() >= 2 {
    let sig_len = read_be16(body, 0)
    sig_len > 0 && 2 + sig_len == body.length()
  } else {
    false
  }
  let ecdhe_ok = if body.length() >= 6 && body[0] == CURVE_TYPE_NAMED {
    let point_len = body[3].to_int()
    let params_len = 4 + point_len
    if point_len > 0 && params_len + 2 <= body.length() {
      let sig_len = read_be16(body, params_len)
      sig_len > 0 && params_len + 2 + sig_len == body.length()
    } else {
      false
    }
  } else {
    false
  }
  if !(ecc_ok || ecdhe_ok) {
    raise InvalidLength
  }
}

///|
fn validate_cert_request_body(body : BytesView) -> Unit raise HandshakeError {
  if body.length() < 1 {
    raise InvalidLength
  }
  let ct_len = body[0].to_int()
  let mut pos = 1
  if ct_len == 0 || pos + ct_len + 2 > body.length() {
    raise InvalidLength
  }
  pos = pos + ct_len
  let ca_list_len = read_be16(body, pos)
  pos = pos + 2
  if pos + ca_list_len != body.length() {
    raise InvalidLength
  }
  while pos < body.length() {
    if pos + 2 > body.length() {
      raise InvalidLength
    }
    let dn_len = read_be16(body, pos)
    pos = pos + 2
    if dn_len == 0 || pos + dn_len > body.length() {
      raise InvalidLength
    }
    pos = pos + dn_len
  }
}

///|
fn validate_cke_body(body : BytesView) -> Unit raise HandshakeError {
  let ecc_or_prefixed_ok = if body.length() >= 2 {
    let ct_len = read_be16(body, 0)
    ct_len > 0 && 2 + ct_len == body.length()
  } else {
    false
  }
  let ecdhe_params_ok = if body.length() >= 4 && body[0] == CURVE_TYPE_NAMED {
    let point_len = body[3].to_int()
    point_len > 0 && 4 + point_len == body.length()
  } else {
    false
  }
  if !(ecc_or_prefixed_ok || ecdhe_params_ok) {
    raise InvalidLength
  }
}

///|
fn validate_cert_verify_body(body : BytesView) -> Unit raise HandshakeError {
  if body.length() < 2 {
    raise InvalidLength
  }
  let sig_len = read_be16(body, 0)
  if sig_len == 0 || 2 + sig_len != body.length() {
    raise InvalidLength
  }
}

///|
fn simple_summary(
  msg_type : Byte,
  msg_type_name : String,
  body_len : Int32,
  total_wire_len : Int32,
) -> HandshakeSummary {
  {
    msg_type,
    msg_type_name,
    body_len,
    total_wire_len,
    protocol_version: 0U,
    cipher_suites: [],
    selected_suite: None,
    cert_count: 0,
    session_id_len: 0,
  }
}

///|
/// Statelessly inspects a single plaintext TLCP handshake frame at the start of `raw`.
///
/// Validates the 4-byte handshake header (`msg_type || uint24_be(body_len)`),
/// enforces `body_len <= MAX_HANDSHAKE_MSG_LEN`, and validates message-specific
/// structural bounds for all 9 GM/T 0024-2023 handshake types without running a
/// stateful session or mutating any state.
pub fn inspect_handshake(
  raw : BytesView,
) -> HandshakeSummary raise HandshakeError {
  let (msg_type, body, total_wire_len) = decode_handshake_frame(raw)
  match msg_type {
    HT_CLIENT_HELLO => inspect_client_hello_body(body, total_wire_len)
    HT_SERVER_HELLO => inspect_server_hello_body(body, total_wire_len)
    HT_CERTIFICATE => inspect_certificate_body(body, total_wire_len)
    HT_SERVER_KEY_EXCHANGE => {
      validate_ske_body(body)
      simple_summary(
        HT_SERVER_KEY_EXCHANGE,
        "ServerKeyExchange",
        body.length(),
        total_wire_len,
      )
    }
    HT_CERTIFICATE_REQUEST => {
      validate_cert_request_body(body)
      simple_summary(
        HT_CERTIFICATE_REQUEST,
        "CertificateRequest",
        body.length(),
        total_wire_len,
      )
    }
    HT_SERVER_HELLO_DONE => {
      if body.length() != 0 {
        raise InvalidLength
      }
      simple_summary(HT_SERVER_HELLO_DONE, "ServerHelloDone", 0, total_wire_len)
    }
    HT_CERTIFICATE_VERIFY => {
      validate_cert_verify_body(body)
      simple_summary(
        HT_CERTIFICATE_VERIFY,
        "CertificateVerify",
        body.length(),
        total_wire_len,
      )
    }
    HT_CLIENT_KEY_EXCHANGE => {
      validate_cke_body(body)
      simple_summary(
        HT_CLIENT_KEY_EXCHANGE,
        "ClientKeyExchange",
        body.length(),
        total_wire_len,
      )
    }
    HT_FINISHED => {
      if body.length() != VERIFY_DATA_LEN {
        raise InvalidLength
      }
      simple_summary(HT_FINISHED, "Finished", body.length(), total_wire_len)
    }
    _ => raise InvalidMessageType(msg_type)
  }
}

///|
/// Statelessly inspects a 2-byte plaintext TLCP Alert payload, returning
/// `(level_byte, description_byte, human_readable_gmt0024_alert_name)`.
pub fn inspect_alert(
  payload : BytesView,
) -> (Byte, Byte, String) raise HandshakeError {
  let alert = decode_alert(payload)
  (alert.level.to_byte(), alert.description.to_byte(), alert.description.name())
}
