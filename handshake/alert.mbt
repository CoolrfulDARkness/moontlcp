///|
/// GM/T 0024-2023 (GB/T 38636-2020) §6.4.2 TLCP 1.1 Alert Protocol.

///|
#derive(Debug, Eq)
pub(all) enum AlertLevel {
  Warning
  Fatal
}

///|
/// Encodes an `AlertLevel` to its wire byte (`1` = Warning, `2` = Fatal).
pub fn AlertLevel::to_byte(self : AlertLevel) -> Byte {
  match self {
    Warning => b'\x01'
    Fatal => b'\x02'
  }
}

///|
/// Decodes an alert level wire byte.
pub fn AlertLevel::from_byte(b : Byte) -> AlertLevel raise HandshakeError {
  match b {
    b'\x01' => Warning
    b'\x02' => Fatal
    _ =>
      raise HandshakeError::DecodeError(
        "invalid alert level: " + b.to_int().to_string(),
      )
  }
}

///|
#derive(Debug, Eq)
pub(all) enum AlertDescription {
  CloseNotify
  UnexpectedMessage
  BadRecordMac
  DecryptionFailed
  RecordOverflow
  HandshakeFailure
  BadCertificate
  UnsupportedCertificate
  CertificateExpired
  CertificateUnknown
  IllegalParameter
  UnknownCa
  DecodeError
  DecryptError
  ProtocolVersion
  InsufficientSecurity
  InternalError
  UnsupportedSite2Site
}

///|
/// Encodes an `AlertDescription` to its RFC / GM/T 0024-2023 alert code.
pub fn AlertDescription::to_byte(self : AlertDescription) -> Byte {
  match self {
    CloseNotify => b'\x00'
    UnexpectedMessage => b'\x0A'
    BadRecordMac => b'\x14'
    DecryptionFailed => b'\x15'
    RecordOverflow => b'\x16'
    HandshakeFailure => b'\x28'
    BadCertificate => b'\x2A'
    UnsupportedCertificate => b'\x2B'
    CertificateExpired => b'\x2D'
    CertificateUnknown => b'\x2E'
    IllegalParameter => b'\x2F'
    UnknownCa => b'\x30'
    AlertDescription::DecodeError => b'\x32'
    DecryptError => b'\x33'
    ProtocolVersion => b'\x46'
    InsufficientSecurity => b'\x47'
    InternalError => b'\x50'
    UnsupportedSite2Site => b'\xC8'
  }
}

///|
/// Decodes an alert description wire byte.
pub fn AlertDescription::from_byte(
  b : Byte,
) -> AlertDescription raise HandshakeError {
  match b {
    b'\x00' => CloseNotify
    b'\x0A' => UnexpectedMessage
    b'\x14' => BadRecordMac
    b'\x15' => DecryptionFailed
    b'\x16' => RecordOverflow
    b'\x28' => HandshakeFailure
    b'\x2A' => BadCertificate
    b'\x2B' => UnsupportedCertificate
    b'\x2D' => CertificateExpired
    b'\x2E' => CertificateUnknown
    b'\x2F' => IllegalParameter
    b'\x30' => UnknownCa
    b'\x32' => AlertDescription::DecodeError
    b'\x33' => DecryptError
    b'\x46' => ProtocolVersion
    b'\x47' => InsufficientSecurity
    b'\x50' => InternalError
    b'\xC8' => UnsupportedSite2Site
    _ =>
      raise HandshakeError::DecodeError(
        "unknown alert description: " + b.to_int().to_string(),
      )
  }
}

///|
#derive(Debug, Eq)
pub(all) struct Alert {
  level : AlertLevel
  description : AlertDescription
}

///|
/// Serializes a 2-byte TLCP `Alert` record payload.
pub fn encode_alert(alert : Alert) -> Bytes {
  Bytes::from_array([alert.level.to_byte(), alert.description.to_byte()])
}

///|
/// Decodes a 2-byte TLCP `Alert` record payload.
pub fn decode_alert(buf : BytesView) -> Alert raise HandshakeError {
  if buf.length() < 2 {
    raise Incomplete
  }
  if buf.length() > 2 {
    raise InvalidLength
  }
  let level = AlertLevel::from_byte(buf[0])
  let description = AlertDescription::from_byte(buf[1])
  { level, description, }
}
