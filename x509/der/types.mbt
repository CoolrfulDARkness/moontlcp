///|
/// Strict ASN.1 DER error types, universal tag constants, and GM / X.509 OID constants.

///|
#derive(Debug, Eq)
pub suberror DerError {
  UnexpectedEof
  InvalidTag(Byte)
  NonCanonicalLength
  IndefiniteLengthNotAllowed
  LengthOverflow
  TrailingData
  InvalidInteger
  InvalidBitString
  InvalidOid
  InvalidPem(String)
}

///|
/// ASN.1 Universal Tag: BOOLEAN (0x01)
pub const TAG_BOOLEAN : Byte = b'\x01'

///|
/// ASN.1 Universal Tag: INTEGER (0x02)
pub const TAG_INTEGER : Byte = b'\x02'

///|
/// ASN.1 Universal Tag: BIT STRING (0x03)
pub const TAG_BIT_STRING : Byte = b'\x03'

///|
/// ASN.1 Universal Tag: OCTET STRING (0x04)
pub const TAG_OCTET_STRING : Byte = b'\x04'

///|
/// ASN.1 Universal Tag: NULL (0x05)
pub const TAG_NULL : Byte = b'\x05'

///|
/// ASN.1 Universal Tag: OBJECT IDENTIFIER (0x06)
pub const TAG_OID : Byte = b'\x06'

///|
/// ASN.1 Universal Tag: UTF8String (0x0C)
pub const TAG_UTF8_STRING : Byte = b'\x0c'

///|
/// ASN.1 Universal Tag: PrintableString (0x13)
pub const TAG_PRINTABLE_STRING : Byte = b'\x13'

///|
/// ASN.1 Universal Tag: IA5String (0x16)
pub const TAG_IA5_STRING : Byte = b'\x16'

///|
/// ASN.1 Universal Tag: UTCTime (0x17)
pub const TAG_UTC_TIME : Byte = b'\x17'

///|
/// ASN.1 Universal Tag: GeneralizedTime (0x18)
pub const TAG_GENERALIZED_TIME : Byte = b'\x18'

///|
/// ASN.1 Universal Tag: SEQUENCE / SEQUENCE OF (constructed, 0x30)
pub const TAG_SEQUENCE : Byte = b'\x30'

///|
/// ASN.1 Universal Tag: SET / SET OF (constructed, 0x31)
pub const TAG_SET : Byte = b'\x31'

///|
/// X9.62 id-ecPublicKey (1.2.840.10045.2.1)
pub const OID_EC_PUBLIC_KEY : String = "1.2.840.10045.2.1"

///|
/// GM/T 0006 SM2 elliptic curve parameter OID (1.2.156.10197.1.301)
pub const OID_SM2_CURVE : String = "1.2.156.10197.1.301"

///|
/// GM/T 0006 / GM/T 0015 SM2-with-SM3 signature algorithm OID (1.2.156.10197.1.501)
pub const OID_SM2_SIGN_SM3 : String = "1.2.156.10197.1.501"

///|
/// GM/T 0006 SM3 cryptographic hash algorithm OID (1.2.156.10197.1.401)
pub const OID_SM3 : String = "1.2.156.10197.1.401"

///|
/// X.520 id-at-commonName (2.5.4.3)
pub const OID_COMMON_NAME : String = "2.5.4.3"

///|
/// X.520 id-at-organizationName (2.5.4.10)
pub const OID_ORGANIZATION : String = "2.5.4.10"

///|
/// X.520 id-at-countryName (2.5.4.6)
pub const OID_COUNTRY : String = "2.5.4.6"

///|
/// RFC 5280 id-ce-keyUsage (2.5.29.15)
pub const OID_KEY_USAGE : String = "2.5.29.15"

///|
/// RFC 5280 id-ce-basicConstraints (2.5.29.19)
pub const OID_BASIC_CONSTRAINTS : String = "2.5.29.19"

///|
/// RFC 5280 id-ce-extKeyUsage (2.5.29.37)
pub const OID_EXT_KEY_USAGE : String = "2.5.29.37"

///|
/// RFC 5280 id-ce-subjectKeyIdentifier (2.5.29.14)
pub const OID_SUBJECT_KEY_ID : String = "2.5.29.14"

///|
/// RFC 5280 id-ce-authorityKeyIdentifier (2.5.29.35)
pub const OID_AUTHORITY_KEY_ID : String = "2.5.29.35"
