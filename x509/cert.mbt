///|
/// GM/T 0015-2023 & RFC 5280 SM2 X.509 v3 Certificate Parser and Verifier.

///|
#derive(Debug, Eq)
pub suberror X509Error {
  DerError(String)
  UnsupportedVersion
  UnsupportedAlgorithm(String)
  InvalidPublicKey
  InvalidSignature
  NotCa
  BadKeyUsage(String)
  ChainVerificationFailed(String)
  DualCertMismatch(String)
  InvalidCertCount(Int32)
}

///|
#derive(Debug, Eq)
pub(all) struct KeyUsage {
  digital_signature : Bool
  content_commitment : Bool
  key_encipherment : Bool
  data_encipherment : Bool
  key_agreement : Bool
  key_cert_sign : Bool
  crl_sign : Bool
}

///|
#derive(Debug, Eq)
pub struct Certificate {
  raw_der : Bytes
  tbs_der : Bytes
  serial : Bytes
  signature_oid : String
  issuer_cn : String
  subject_cn : String
  not_before : String
  not_after : String
  public_key : @sm2.PublicKey
  is_ca : Bool
  key_usage : KeyUsage?
  signature_der : Bytes
}

///|
fn map_der_err(e : @der.DerError) -> X509Error {
  match e {
    @der.DerError::UnexpectedEof => DerError("unexpected EOF")
    @der.DerError::InvalidTag(t) =>
      DerError("invalid tag: " + t.to_int().to_string())
    @der.DerError::NonCanonicalLength => DerError("non-canonical length")
    @der.DerError::IndefiniteLengthNotAllowed =>
      DerError("indefinite length not allowed")
    @der.DerError::LengthOverflow => DerError("length overflow")
    @der.DerError::TrailingData => DerError("trailing data")
    @der.DerError::InvalidInteger => DerError("invalid integer")
    @der.DerError::InvalidBitString => DerError("invalid bit string")
    @der.DerError::InvalidOid => DerError("invalid OID")
    @der.DerError::InvalidPem(msg) => DerError("invalid PEM: " + msg)
  }
}

///|
/// Parse an AlgorithmIdentifier for signature algorithm.
/// Accepts optional NULL or omitted parameters (OpenSSL 3.5.6 omits parameters for SM2-with-SM3).
fn parse_sig_algorithm(r : @der.DerReader) -> String raise X509Error {
  let seq_body = r.expect_tag(@der.TAG_SEQUENCE) catch {
    e => raise map_der_err(e)
  }
  let ar = @der.DerReader::new(seq_body)
  let oid = ar.read_oid() catch { e => raise map_der_err(e) }
  if !ar.is_empty() {
    ar.read_null() catch {
      e => raise map_der_err(e)
    }
    ar.expect_end() catch {
      e => raise map_der_err(e)
    }
  }
  if oid != @der.OID_SM2_SIGN_SM3 {
    raise UnsupportedAlgorithm(oid)
  }
  oid
}

///|
/// Parse an X.501 Name (SEQUENCE OF RelativeDistinguishedName) and extract the Common Name (CN).
fn parse_name_cn(r : @der.DerReader) -> String raise X509Error {
  let name_body = r.expect_tag(@der.TAG_SEQUENCE) catch {
    e => raise map_der_err(e)
  }
  let nr = @der.DerReader::new(name_body)
  let mut cn = ""
  while !nr.is_empty() {
    let rdn_body = nr.expect_tag(@der.TAG_SET) catch {
      e => raise map_der_err(e)
    }
    let rr = @der.DerReader::new(rdn_body)
    while !rr.is_empty() {
      let atv_body = rr.expect_tag(@der.TAG_SEQUENCE) catch {
        e => raise map_der_err(e)
      }
      let ar = @der.DerReader::new(atv_body)
      let attr_oid = ar.read_oid() catch { e => raise map_der_err(e) }
      if attr_oid == @der.OID_COMMON_NAME {
        cn = ar.read_string() catch { e => raise map_der_err(e) }
      } else {
        ignore(ar.read_tlv() catch { e => raise map_der_err(e) })
      }
      ar.expect_end() catch {
        e => raise map_der_err(e)
      }
    }
  }
  cn
}

///|
fn parse_time(r : @der.DerReader) -> String raise X509Error {
  match r.peek_tag() {
    Some(tag) if tag == @der.TAG_UTC_TIME || tag == @der.TAG_GENERALIZED_TIME =>
      r.read_string() catch {
        e => raise map_der_err(e)
      }
    Some(tag) =>
      raise DerError("expected time tag, got " + tag.to_int().to_string())
    None => raise DerError("unexpected EOF reading time")
  }
}

///|
/// Parse SubjectPublicKeyInfo for SM2 (`id-ecPublicKey` + `sm2p256v1`).
fn parse_sm2_spki(r : @der.DerReader) -> @sm2.PublicKey raise X509Error {
  let spki_body = r.expect_tag(@der.TAG_SEQUENCE) catch {
    e => raise map_der_err(e)
  }
  let sr = @der.DerReader::new(spki_body)
  let alg_body = sr.expect_tag(@der.TAG_SEQUENCE) catch {
    e => raise map_der_err(e)
  }
  let ar = @der.DerReader::new(alg_body)
  let alg_oid = ar.read_oid() catch { e => raise map_der_err(e) }
  if alg_oid != @der.OID_EC_PUBLIC_KEY {
    raise UnsupportedAlgorithm(alg_oid)
  }
  let curve_oid = ar.read_oid() catch { e => raise map_der_err(e) }
  if curve_oid != @der.OID_SM2_CURVE {
    raise UnsupportedAlgorithm(curve_oid)
  }
  ar.expect_end() catch {
    e => raise map_der_err(e)
  }
  let (pk_bits, pk_unused) = sr.read_bit_string() catch {
    e => raise map_der_err(e)
  }
  if pk_unused != 0 {
    raise InvalidPublicKey
  }
  sr.expect_end() catch {
    e => raise map_der_err(e)
  }
  @sm2.PublicKey::from_bytes(pk_bits.to_owned()) catch {
    _ => raise InvalidPublicKey
  }
}

///|
fn bit_is_set(bits : BytesView, total_bits : Int32, idx : Int32) -> Bool {
  if idx >= total_bits {
    return false
  }
  let byte_idx = idx / 8
  let bit_mask = 0x80 >> (idx % 8)
  (bits[byte_idx].to_int() & bit_mask) != 0
}

///|
fn parse_key_usage(ext_val : BytesView) -> KeyUsage raise X509Error {
  let kr = @der.DerReader::new(ext_val)
  let (bits, unused) = kr.read_bit_string() catch { e => raise map_der_err(e) }
  kr.expect_end() catch {
    e => raise map_der_err(e)
  }
  let total_bits = bits.length() * 8 - unused
  {
    digital_signature: bit_is_set(bits, total_bits, 0),
    content_commitment: bit_is_set(bits, total_bits, 1),
    key_encipherment: bit_is_set(bits, total_bits, 2),
    data_encipherment: bit_is_set(bits, total_bits, 3),
    key_agreement: bit_is_set(bits, total_bits, 4),
    key_cert_sign: bit_is_set(bits, total_bits, 5),
    crl_sign: bit_is_set(bits, total_bits, 6),
  }
}

///|
fn parse_basic_constraints(ext_val : BytesView) -> Bool raise X509Error {
  let br = @der.DerReader::new(ext_val)
  let seq_body = br.expect_tag(@der.TAG_SEQUENCE) catch {
    e => raise map_der_err(e)
  }
  br.expect_end() catch {
    e => raise map_der_err(e)
  }
  let ir = @der.DerReader::new(seq_body)
  let mut is_ca = false
  if ir.peek_tag() == Some(@der.TAG_BOOLEAN) {
    is_ca = ir.read_boolean() catch { e => raise map_der_err(e) }
  }
  // Optional pathLenConstraint INTEGER
  if !ir.is_empty() {
    ignore(ir.read_int_u64() catch { e => raise map_der_err(e) })
  }
  ir.expect_end() catch {
    e => raise map_der_err(e)
  }
  is_ca
}

///|
/// Parse a DER-encoded GM SM2 X.509 v3 certificate.
/// Compatible with certificates generated by OpenSSL 3.5.6 and `build_sm2_cert`.
pub fn Certificate::from_der(der_bytes : Bytes) -> Certificate raise X509Error {
  let outer = @der.DerReader::new(der_bytes[:])
  let cert_body = outer.expect_tag(@der.TAG_SEQUENCE) catch {
    e => raise map_der_err(e)
  }
  outer.expect_end() catch {
    e => raise map_der_err(e)
  }
  let cr = @der.DerReader::new(cert_body)
  // Extract exact raw TBSCertificate TLV bytes for signature verification.
  let (tbs_tag, tbs_body, tbs_full) = cr.read_tlv_with_raw() catch {
    e => raise map_der_err(e)
  }
  if tbs_tag != @der.TAG_SEQUENCE {
    raise DerError("expected SEQUENCE for TBSCertificate")
  }
  let tbs_der = tbs_full.to_owned()
  let outer_sig_oid = parse_sig_algorithm(cr)
  let (sig_bits, sig_unused) = cr.read_bit_string() catch {
    e => raise map_der_err(e)
  }
  if sig_unused != 0 {
    raise InvalidSignature
  }
  let signature_der = sig_bits.to_owned()
  cr.expect_end() catch {
    e => raise map_der_err(e)
  }

  // Parse TBSCertificate contents.
  let tbs = @der.DerReader::new(tbs_body)
  // Version [0] EXPLICIT INTEGER DEFAULT v1 (must be v3 == 2).
  let version_opt = tbs.read_optional_context(0) catch {
    e => raise map_der_err(e)
  }
  match version_opt {
    None => raise UnsupportedVersion
    Some(v_bytes) => {
      let vr = @der.DerReader::new(v_bytes)
      let ver = vr.read_int_u64() catch { e => raise map_der_err(e) }
      vr.expect_end() catch {
        e => raise map_der_err(e)
      }
      if ver != 2UL {
        raise UnsupportedVersion
      }
    }
  }
  let serial = (tbs.read_uint_bytes() catch { e => raise map_der_err(e) }).to_owned()
  let tbs_sig_oid = parse_sig_algorithm(tbs)
  if tbs_sig_oid != outer_sig_oid {
    raise UnsupportedAlgorithm(tbs_sig_oid)
  }
  let issuer_cn = parse_name_cn(tbs)
  let val_body = tbs.expect_tag(@der.TAG_SEQUENCE) catch {
    e => raise map_der_err(e)
  }
  let vr = @der.DerReader::new(val_body)
  let not_before = parse_time(vr)
  let not_after = parse_time(vr)
  vr.expect_end() catch {
    e => raise map_der_err(e)
  }
  let subject_cn = parse_name_cn(tbs)
  let public_key = parse_sm2_spki(tbs)

  // Skip optional [1] IMPLICIT issuerUniqueID (0x81) and [2] IMPLICIT subjectUniqueID (0x82).
  if tbs.peek_tag() == Some(b'\x81') {
    ignore(tbs.read_tlv() catch { e => raise map_der_err(e) })
  }
  if tbs.peek_tag() == Some(b'\x82') {
    ignore(tbs.read_tlv() catch { e => raise map_der_err(e) })
  }

  // Parse optional [3] EXPLICIT extensions.
  let mut is_ca = false
  let mut key_usage : KeyUsage? = None
  let ext_opt = tbs.read_optional_context(3) catch { e => raise map_der_err(e) }
  match ext_opt {
    Some(ext_wrap) => {
      let wr = @der.DerReader::new(ext_wrap)
      let exts_body = wr.expect_tag(@der.TAG_SEQUENCE) catch {
        e => raise map_der_err(e)
      }
      wr.expect_end() catch {
        e => raise map_der_err(e)
      }
      let er = @der.DerReader::new(exts_body)
      while !er.is_empty() {
        let ext_body = er.expect_tag(@der.TAG_SEQUENCE) catch {
          e => raise map_der_err(e)
        }
        let xr = @der.DerReader::new(ext_body)
        let ext_oid = xr.read_oid() catch { e => raise map_der_err(e) }
        let mut critical = false
        if xr.peek_tag() == Some(@der.TAG_BOOLEAN) {
          critical = xr.read_boolean() catch { e => raise map_der_err(e) }
        }
        let ext_val = xr.read_octet_string() catch { e => raise map_der_err(e) }
        xr.expect_end() catch {
          e => raise map_der_err(e)
        }
        if ext_oid == @der.OID_BASIC_CONSTRAINTS {
          is_ca = parse_basic_constraints(ext_val)
        } else if ext_oid == @der.OID_KEY_USAGE {
          key_usage = Some(parse_key_usage(ext_val))
        } else if critical && ext_oid != @der.OID_EXT_KEY_USAGE {
          raise UnsupportedAlgorithm(
            "unsupported critical extension: " + ext_oid,
          )
        }
      }
    }
    None => ()
  }
  tbs.expect_end() catch {
    e => raise map_der_err(e)
  }

  {
    raw_der: der_bytes,
    tbs_der,
    serial,
    signature_oid: outer_sig_oid,
    issuer_cn,
    subject_cn,
    not_before,
    not_after,
    public_key,
    is_ca,
    key_usage,
    signature_der,
  }
}

///|
/// Parse all PEM-encoded X.509 certificates from `pem`.
pub fn Certificate::from_pem(
  pem : String,
) -> Array[Certificate] raise X509Error {
  let blocks = @der.pem_decode_all(pem) catch { e => raise map_der_err(e) }
  let certs : Array[Certificate] = []
  for i = 0; i < blocks.length(); i = i + 1 {
    let b = blocks[i]
    if b.label == "CERTIFICATE" ||
      b.label == "X509 CERTIFICATE" ||
      b.label == "TRUSTED CERTIFICATE" {
      certs.push(Certificate::from_der(b.data))
    }
  }
  certs
}

///|
/// Encode this certificate as a PEM `CERTIFICATE` block.
pub fn Certificate::to_pem(self : Certificate) -> String {
  @der.pem_encode("CERTIFICATE", self.raw_der)
}

///|
/// Verify that `self` was validly issued and signed by `issuer`.
/// Enforces:
/// 1. `issuer.is_ca` must be `true` (else `NotCa`).
/// 2. If `issuer.key_usage` is present, `key_cert_sign` must be `true` (else `BadKeyUsage`).
/// 3. `self.issuer_cn == issuer.subject_cn` (else `ChainVerificationFailed`).
/// 4. SM2-with-SM3 signature verification over `self.tbs_der` with `DEFAULT_SM2_ID` (else `InvalidSignature`).
pub fn Certificate::verify_issued_by(
  self : Certificate,
  issuer : Certificate,
) -> Unit raise X509Error {
  if !issuer.is_ca {
    raise NotCa
  }
  match issuer.key_usage {
    Some(ku) =>
      if !ku.key_cert_sign {
        raise BadKeyUsage("issuer certificate lacks keyCertSign")
      }
    None => ()
  }
  if self.issuer_cn != issuer.subject_cn {
    raise ChainVerificationFailed(
      "issuer CN mismatch: cert expects '" +
      self.issuer_cn +
      "', issuer is '" +
      issuer.subject_cn +
      "'",
    )
  }
  if !@sm2.verify_der(
      issuer.public_key,
      @sm2.DEFAULT_SM2_ID,
      self.tbs_der,
      self.signature_der,
    ) {
    raise InvalidSignature
  }
}
