///|
/// GM/T 0024-2023 (GB/T 38636-2020) §6.4 TLCP 1.1 Handshake Messages & Framing.

///|
pub const HT_CLIENT_HELLO : Byte = b'\x01'

///|
pub const HT_SERVER_HELLO : Byte = b'\x02'

///|
pub const HT_CERTIFICATE : Byte = b'\x0B'

///|
pub const HT_SERVER_KEY_EXCHANGE : Byte = b'\x0C'

///|
pub const HT_CERTIFICATE_REQUEST : Byte = b'\x0D'

///|
pub const HT_SERVER_HELLO_DONE : Byte = b'\x0E'

///|
pub const HT_CERTIFICATE_VERIFY : Byte = b'\x0F'

///|
pub const HT_CLIENT_KEY_EXCHANGE : Byte = b'\x10'

///|
pub const HT_FINISHED : Byte = b'\x14'

///|
const RANDOM_LEN : Int32 = 32

///|
const MAX_SESSION_ID_LEN : Int32 = 32

///|
const VERIFY_DATA_LEN : Int32 = 12

///|
#derive(Debug, Eq)
pub(all) struct ClientHello {
  version_major : Byte
  version_minor : Byte
  random : Bytes
  session_id : Bytes
  cipher_suites : Array[UInt32]
  compression_methods : Bytes
}

///|
#derive(Debug, Eq)
pub(all) struct ServerHello {
  version_major : Byte
  version_minor : Byte
  random : Bytes
  session_id : Bytes
  cipher_suite : CipherSuite
  compression_method : Byte
}

///|
#derive(Debug, Eq)
pub(all) struct CertificateMsg {
  certificates : Array[Bytes]
}

///|
#derive(Debug, Eq)
pub(all) enum ServerKeyExchange {
  Ecc(Bytes)
  Ecdhe(Bytes, Bytes)
}

///|
#derive(Debug, Eq)
pub(all) struct CertificateRequest {
  cert_types : Bytes
  ca_names : Array[Bytes]
}

///|
#derive(Debug, Eq)
pub(all) enum ClientKeyExchange {
  Ecc(Bytes)
  Ecdhe(Bytes)
}

///|
#derive(Debug, Eq)
pub(all) struct CertificateVerify {
  signature : Bytes
}

///|
#derive(Debug, Eq)
pub(all) struct Finished {
  verify_data : Bytes
}

///|
#derive(Debug, Eq)
pub(all) enum HandshakeMsg {
  ClientHello(ClientHello)
  ServerHello(ServerHello)
  Certificate(CertificateMsg)
  ServerKeyExchange(ServerKeyExchange)
  CertificateRequest(CertificateRequest)
  ServerHelloDone
  CertificateVerify(CertificateVerify)
  ClientKeyExchange(ClientKeyExchange)
  Finished(Finished)
}

///|
fn push_u16(out : Array[Byte], v : UInt32) -> Unit {
  out.push(((v >> 8) & 0xFFU).to_byte())
  out.push((v & 0xFFU).to_byte())
}

///|
fn push_u24(out : Array[Byte], v : Int32) -> Unit {
  out.push(((v >> 16) & 0xFF).to_byte())
  out.push(((v >> 8) & 0xFF).to_byte())
  out.push((v & 0xFF).to_byte())
}

///|
fn push_bytes(out : Array[Byte], data : Bytes) -> Unit {
  for i = 0; i < data.length(); i = i + 1 {
    out.push(data[i])
  }
}

///|
fn read_be16(buf : BytesView, off : Int32) -> Int32 {
  (buf[off].to_int() << 8) | buf[off + 1].to_int()
}

///|
fn read_be24(buf : BytesView, off : Int32) -> Int32 {
  (buf[off].to_int() << 16) |
  (buf[off + 1].to_int() << 8) |
  buf[off + 2].to_int()
}

///|
fn slice_bytes(buf : BytesView, off : Int32, len : Int32) -> Bytes {
  let out = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = buf[off + i]
  }
  Bytes::from_array(out)
}

///|
fn is_supported_sm2_curve(curve_id : UInt32) -> Bool {
  curve_id == NAMED_CURVE_SM2P256V1 ||
  curve_id == 0x0020U ||
  curve_id == 0x001DU
}

///|
/// Builds the GB/T 38636-2020 §6.4.5.4 ECC `ServerKeyExchange` TBS (to-be-signed)
/// input: `client_random || server_random || uint24(len(enc_cert)) || enc_cert`.
pub fn build_ecc_ske_tbs(
  client_random : Bytes,
  server_random : Bytes,
  enc_cert_der : Bytes,
) -> Bytes {
  let out : Array[Byte] = Array(
    capacity=client_random.length() +
      server_random.length() +
      3 +
      enc_cert_der.length(),
  )
  push_bytes(out, client_random)
  push_bytes(out, server_random)
  push_u24(out, enc_cert_der.length())
  push_bytes(out, enc_cert_der)
  Bytes::from_array(out)
}

///|
/// Builds ECDHE `ServerECDHParams`:
/// `CURVE_TYPE_NAMED (0x03) || be16(curve_id) || u8(len(pub)) || pub_uncompressed`.
pub fn build_ecdhe_params(curve_id : UInt32, pub_uncompressed : Bytes) -> Bytes {
  let out : Array[Byte] = Array(capacity=4 + pub_uncompressed.length())
  out.push(CURVE_TYPE_NAMED)
  push_u16(out, curve_id)
  out.push((pub_uncompressed.length() & 0xFF).to_byte())
  push_bytes(out, pub_uncompressed)
  Bytes::from_array(out)
}

///|
/// Parses ECDHE `ServerECDHParams` into `(curve_id, public_point_bytes)`.
/// Accepts SM2 named curve IDs `0x0029` (RFC 8998), `0x0020`, and `0x001D`.
pub fn parse_ecdhe_params(
  params : BytesView,
) -> (UInt32, Bytes) raise HandshakeError {
  if params.length() < 4 {
    raise InvalidLength
  }
  if params[0] != CURVE_TYPE_NAMED {
    raise HandshakeError::DecodeError(
      "unsupported EC curve type: " + params[0].to_int().to_string(),
    )
  }
  let curve_id = read_be16(params, 1).reinterpret_as_uint()
  if !is_supported_sm2_curve(curve_id) {
    raise HandshakeError::DecodeError(
      "unsupported SM2 named curve: " + curve_id.to_string(),
    )
  }
  let point_len = params[3].to_int()
  if point_len == 0 || 4 + point_len != params.length() {
    raise InvalidLength
  }
  (curve_id, slice_bytes(params, 4, point_len))
}

///|
/// Builds the ECDHE `ServerKeyExchange` TBS (to-be-signed) input:
/// `client_random || server_random || params`.
pub fn build_ecdhe_ske_tbs(
  client_random : Bytes,
  server_random : Bytes,
  params : Bytes,
) -> Bytes {
  let out : Array[Byte] = Array(
    capacity=client_random.length() + server_random.length() + params.length(),
  )
  push_bytes(out, client_random)
  push_bytes(out, server_random)
  push_bytes(out, params)
  Bytes::from_array(out)
}

///|
/// Encodes a `HandshakeMsg` into its complete wire frame:
/// `msg_type (1B) || uint24_be(body.length()) || body`.
pub fn encode_handshake_msg(msg : HandshakeMsg) -> Bytes {
  let body : Array[Byte] = []
  let msg_type = match msg {
    ClientHello(ch) => {
      body.push(ch.version_major)
      body.push(ch.version_minor)
      push_bytes(body, ch.random)
      body.push((ch.session_id.length() & 0xFF).to_byte())
      push_bytes(body, ch.session_id)
      push_u16(body, (ch.cipher_suites.length() * 2).reinterpret_as_uint())
      for i = 0; i < ch.cipher_suites.length(); i = i + 1 {
        push_u16(body, ch.cipher_suites[i])
      }
      body.push((ch.compression_methods.length() & 0xFF).to_byte())
      push_bytes(body, ch.compression_methods)
      HT_CLIENT_HELLO
    }
    ServerHello(sh) => {
      body.push(sh.version_major)
      body.push(sh.version_minor)
      push_bytes(body, sh.random)
      body.push((sh.session_id.length() & 0xFF).to_byte())
      push_bytes(body, sh.session_id)
      push_u16(body, sh.cipher_suite.to_u16())
      body.push(sh.compression_method)
      HT_SERVER_HELLO
    }
    Certificate(cert_msg) => {
      let mut list_len = 0
      for i = 0; i < cert_msg.certificates.length(); i = i + 1 {
        list_len = list_len + 3 + cert_msg.certificates[i].length()
      }
      push_u24(body, list_len)
      for i = 0; i < cert_msg.certificates.length(); i = i + 1 {
        let cert = cert_msg.certificates[i]
        push_u24(body, cert.length())
        push_bytes(body, cert)
      }
      HT_CERTIFICATE
    }
    ServerKeyExchange(ske) => {
      match ske {
        ServerKeyExchange::Ecc(sig) => {
          push_u16(body, sig.length().reinterpret_as_uint())
          push_bytes(body, sig)
        }
        ServerKeyExchange::Ecdhe(params, sig) => {
          push_bytes(body, params)
          push_u16(body, sig.length().reinterpret_as_uint())
          push_bytes(body, sig)
        }
      }
      HT_SERVER_KEY_EXCHANGE
    }
    CertificateRequest(cr) => {
      body.push((cr.cert_types.length() & 0xFF).to_byte())
      push_bytes(body, cr.cert_types)
      let mut ca_list_len = 0
      for i = 0; i < cr.ca_names.length(); i = i + 1 {
        ca_list_len = ca_list_len + 2 + cr.ca_names[i].length()
      }
      push_u16(body, ca_list_len.reinterpret_as_uint())
      for i = 0; i < cr.ca_names.length(); i = i + 1 {
        let dn = cr.ca_names[i]
        push_u16(body, dn.length().reinterpret_as_uint())
        push_bytes(body, dn)
      }
      HT_CERTIFICATE_REQUEST
    }
    ServerHelloDone => HT_SERVER_HELLO_DONE
    CertificateVerify(cv) => {
      push_u16(body, cv.signature.length().reinterpret_as_uint())
      push_bytes(body, cv.signature)
      HT_CERTIFICATE_VERIFY
    }
    ClientKeyExchange(cke) => {
      match cke {
        ClientKeyExchange::Ecc(ct) => {
          push_u16(body, ct.length().reinterpret_as_uint())
          push_bytes(body, ct)
        }
        ClientKeyExchange::Ecdhe(params) => push_bytes(body, params)
      }
      HT_CLIENT_KEY_EXCHANGE
    }
    Finished(fin) => {
      push_bytes(body, fin.verify_data)
      HT_FINISHED
    }
  }
  let frame : Array[Byte] = Array(capacity=4 + body.length())
  frame.push(msg_type)
  push_u24(frame, body.length())
  for i = 0; i < body.length(); i = i + 1 {
    frame.push(body[i])
  }
  Bytes::from_array(frame)
}

///|
/// Decodes one handshake frame header + body slice from a possibly coalesced
/// handshake stream, returning `(msg_type, body_view, total_bytes_consumed)`.
/// Raises `Incomplete` if fewer than `4 + body_len` bytes are available.
pub fn decode_handshake_frame(
  buf : BytesView,
) -> (Byte, BytesView, Int32) raise HandshakeError {
  if buf.length() < 4 {
    raise Incomplete
  }
  let msg_type = buf[0]
  let body_len = read_be24(buf, 1)
  let total = 4 + body_len
  if buf.length() < total {
    raise Incomplete
  }
  (msg_type, buf[4:total], total)
}

///|
/// Validates optional trailing TLS extensions in Hello messages.
fn validate_optional_extensions(
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
  if pos + 2 + ext_len != body.length() {
    raise InvalidLength
  }
}

///|
fn decode_client_hello(body : BytesView) -> ClientHello raise HandshakeError {
  // Minimum: 2(ver) + 32(random) + 1(sid_len) + 2(cs_len) + 2(1 cs) + 1(cm_len) + 1(1 cm) = 41
  if body.length() < 2 + RANDOM_LEN + 1 {
    raise InvalidLength
  }
  let version_major = body[0]
  let version_minor = body[1]
  if version_major != @record.TLCP_VERSION_MAJOR ||
    version_minor != @record.TLCP_VERSION_MINOR {
    raise InvalidVersion(version_major, version_minor)
  }
  let random = slice_bytes(body, 2, RANDOM_LEN)
  let mut pos = 2 + RANDOM_LEN
  let sid_len = body[pos].to_int()
  pos = pos + 1
  if sid_len > MAX_SESSION_ID_LEN || pos + sid_len > body.length() {
    raise InvalidLength
  }
  let session_id = slice_bytes(body, pos, sid_len)
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
  let compression_methods = slice_bytes(body, pos, cm_len)
  pos = pos + cm_len
  validate_optional_extensions(body, pos)
  {
    version_major,
    version_minor,
    random,
    session_id,
    cipher_suites,
    compression_methods,
  }
}

///|
fn decode_server_hello(body : BytesView) -> ServerHello raise HandshakeError {
  if body.length() < 2 + RANDOM_LEN + 1 {
    raise InvalidLength
  }
  let version_major = body[0]
  let version_minor = body[1]
  if version_major != @record.TLCP_VERSION_MAJOR ||
    version_minor != @record.TLCP_VERSION_MINOR {
    raise InvalidVersion(version_major, version_minor)
  }
  let random = slice_bytes(body, 2, RANDOM_LEN)
  let mut pos = 2 + RANDOM_LEN
  let sid_len = body[pos].to_int()
  pos = pos + 1
  if sid_len > MAX_SESSION_ID_LEN || pos + sid_len + 3 > body.length() {
    raise InvalidLength
  }
  let session_id = slice_bytes(body, pos, sid_len)
  pos = pos + sid_len
  let cs_u16 = read_be16(body, pos).reinterpret_as_uint()
  pos = pos + 2
  let cipher_suite = match CipherSuite::from_u16(cs_u16) {
    Some(cs) => cs
    None => raise UnsupportedCipherSuite
  }
  let compression_method = body[pos]
  pos = pos + 1
  validate_optional_extensions(body, pos)
  {
    version_major,
    version_minor,
    random,
    session_id,
    cipher_suite,
    compression_method,
  }
}

///|
fn decode_certificate_msg(
  body : BytesView,
) -> CertificateMsg raise HandshakeError {
  if body.length() < 3 {
    raise InvalidLength
  }
  let total_len = read_be24(body, 0)
  if 3 + total_len != body.length() {
    raise InvalidLength
  }
  let certificates : Array[Bytes] = []
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
    certificates.push(slice_bytes(body, pos, cert_len))
    pos = pos + cert_len
  }
  { certificates, }
}

///|
fn decode_server_key_exchange(
  body : BytesView,
  is_ecdhe : Bool,
) -> ServerKeyExchange raise HandshakeError {
  if !is_ecdhe {
    if body.length() < 2 {
      raise InvalidLength
    }
    let sig_len = read_be16(body, 0)
    if sig_len == 0 || 2 + sig_len != body.length() {
      raise InvalidLength
    }
    ServerKeyExchange::Ecc(slice_bytes(body, 2, sig_len))
  } else {
    if body.length() < 4 {
      raise InvalidLength
    }
    let point_len = body[3].to_int()
    let params_len = 4 + point_len
    if point_len == 0 || params_len + 2 > body.length() {
      raise InvalidLength
    }
    // Validate curve type & SM2 curve ID
    ignore(parse_ecdhe_params(body[:params_len]))
    let sig_len = read_be16(body, params_len)
    if sig_len == 0 || params_len + 2 + sig_len != body.length() {
      raise InvalidLength
    }
    ServerKeyExchange::Ecdhe(
      slice_bytes(body, 0, params_len),
      slice_bytes(body, params_len + 2, sig_len),
    )
  }
}

///|
fn decode_certificate_request(
  body : BytesView,
) -> CertificateRequest raise HandshakeError {
  if body.length() < 1 {
    raise InvalidLength
  }
  let ct_len = body[0].to_int()
  let mut pos = 1
  if ct_len == 0 || pos + ct_len + 2 > body.length() {
    raise InvalidLength
  }
  let cert_types = slice_bytes(body, pos, ct_len)
  pos = pos + ct_len
  let ca_list_len = read_be16(body, pos)
  pos = pos + 2
  if pos + ca_list_len != body.length() {
    raise InvalidLength
  }
  let ca_names : Array[Bytes] = []
  while pos < body.length() {
    if pos + 2 > body.length() {
      raise InvalidLength
    }
    let dn_len = read_be16(body, pos)
    pos = pos + 2
    if dn_len == 0 || pos + dn_len > body.length() {
      raise InvalidLength
    }
    ca_names.push(slice_bytes(body, pos, dn_len))
    pos = pos + dn_len
  }
  { cert_types, ca_names, }
}

///|
fn decode_client_key_exchange(
  body : BytesView,
  is_ecdhe : Bool,
) -> ClientKeyExchange raise HandshakeError {
  if !is_ecdhe {
    if body.length() < 2 {
      raise InvalidLength
    }
    let ct_len = read_be16(body, 0)
    if ct_len == 0 || 2 + ct_len != body.length() {
      raise InvalidLength
    }
    ClientKeyExchange::Ecc(slice_bytes(body, 2, ct_len))
  } else {
    if body.length() == 0 {
      raise InvalidLength
    }
    if body.length() == 2 && body[0] == b'\x00' && body[1] == b'\x00' {
      raise InvalidLength
    }
    // Support optional 2-byte length prefix used by some TLCP peers
    if body.length() >= 3 && read_be16(body, 0) == body.length() - 2 {
      ClientKeyExchange::Ecdhe(slice_bytes(body, 2, body.length() - 2))
    } else {
      ClientKeyExchange::Ecdhe(slice_bytes(body, 0, body.length()))
    }
  }
}

///|
fn decode_certificate_verify(
  body : BytesView,
) -> CertificateVerify raise HandshakeError {
  if body.length() < 2 {
    raise InvalidLength
  }
  let sig_len = read_be16(body, 0)
  if sig_len == 0 || 2 + sig_len != body.length() {
    raise InvalidLength
  }
  { signature: slice_bytes(body, 2, sig_len), }
}

///|
fn decode_finished(body : BytesView) -> Finished raise HandshakeError {
  if body.length() != VERIFY_DATA_LEN {
    raise InvalidLength
  }
  { verify_data: slice_bytes(body, 0, VERIFY_DATA_LEN), }
}

///|
/// Decodes a handshake message body according to its `msg_type` and key-exchange
/// mode (`is_ecdhe`).
pub fn decode_handshake_msg(
  msg_type : Byte,
  body : BytesView,
  is_ecdhe : Bool,
) -> HandshakeMsg raise HandshakeError {
  match msg_type {
    HT_CLIENT_HELLO => ClientHello(decode_client_hello(body))
    HT_SERVER_HELLO => ServerHello(decode_server_hello(body))
    HT_CERTIFICATE => Certificate(decode_certificate_msg(body))
    HT_SERVER_KEY_EXCHANGE =>
      ServerKeyExchange(decode_server_key_exchange(body, is_ecdhe))
    HT_CERTIFICATE_REQUEST =>
      CertificateRequest(decode_certificate_request(body))
    HT_SERVER_HELLO_DONE => {
      if body.length() != 0 {
        raise InvalidLength
      }
      ServerHelloDone
    }
    HT_CERTIFICATE_VERIFY => CertificateVerify(decode_certificate_verify(body))
    HT_CLIENT_KEY_EXCHANGE =>
      ClientKeyExchange(decode_client_key_exchange(body, is_ecdhe))
    HT_FINISHED => Finished(decode_finished(body))
    _ => raise InvalidMessageType(msg_type)
  }
}
