///|
/// GM/T 0024-2023 (GB/T 38636-2020) TLCP 1.1 cipher suites, curve identifiers,
/// and handshake error definitions.

///|
pub const CURVE_TYPE_NAMED : Byte = b'\x03'

///|
/// RFC 8998 / GM/T 0024-2023 SM2 named curve identifier (`sm2p256v1`).
pub const NAMED_CURVE_SM2P256V1 : UInt32 = 0x0029U

///|
#derive(Debug, Eq)
pub suberror HandshakeError {
  Incomplete
  InvalidMessageType(Byte)
  InvalidLength
  InvalidVersion(Byte, Byte)
  UnsupportedCipherSuite
  DecodeError(String)
}

///|
/// The 4 standard GM/T 0024-2023 TLCP 1.1 cipher suites.
#derive(Debug, Eq)
pub(all) enum CipherSuite {
  EcdheSm4CbcSm3
  EccSm4CbcSm3
  EcdheSm4GcmSm3
  EccSm4GcmSm3
}

///|
/// Returns the 16-bit GM/T 0024-2023 wire code for a cipher suite.
pub fn CipherSuite::to_u16(self : CipherSuite) -> UInt32 {
  match self {
    EcdheSm4CbcSm3 => 0xE011U
    EccSm4CbcSm3 => 0xE013U
    EcdheSm4GcmSm3 => 0xE051U
    EccSm4GcmSm3 => 0xE053U
  }
}

///|
/// Decodes a 16-bit wire code into a supported TLCP 1.1 cipher suite.
pub fn CipherSuite::from_u16(code : UInt32) -> CipherSuite? {
  match code {
    0xE011U => Some(EcdheSm4CbcSm3)
    0xE013U => Some(EccSm4CbcSm3)
    0xE051U => Some(EcdheSm4GcmSm3)
    0xE053U => Some(EccSm4GcmSm3)
    _ => None
  }
}

///|
/// Returns `true` if the cipher suite uses SM4-GCM AEAD (otherwise SM4-CBC-HMAC-SM3).
pub fn CipherSuite::is_gcm(self : CipherSuite) -> Bool {
  match self {
    EcdheSm4GcmSm3 | EccSm4GcmSm3 => true
    EcdheSm4CbcSm3 | EccSm4CbcSm3 => false
  }
}

///|
/// Returns `true` if the cipher suite uses ephemeral ECDHE key exchange (otherwise static ECC).
pub fn CipherSuite::is_ecdhe(self : CipherSuite) -> Bool {
  match self {
    EcdheSm4CbcSm3 | EcdheSm4GcmSm3 => true
    EccSm4CbcSm3 | EccSm4GcmSm3 => false
  }
}

///|
/// Returns the standard GM/T 0024-2023 name of the cipher suite.
pub fn CipherSuite::name(self : CipherSuite) -> String {
  match self {
    EcdheSm4CbcSm3 => "ECDHE_SM4_CBC_SM3"
    EccSm4CbcSm3 => "ECC_SM4_CBC_SM3"
    EcdheSm4GcmSm3 => "ECDHE_SM4_GCM_SM3"
    EccSm4GcmSm3 => "ECC_SM4_GCM_SM3"
  }
}
