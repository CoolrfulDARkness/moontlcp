///|
/// Standard GM/T 0015-2023 & RFC 5280 SM2 X.509 v3 Certificate Builder and Test PKI Generator.

///|
#derive(Debug, Eq)
pub(all) struct CertSpec {
  serial : UInt64
  subject_cn : String
  issuer_cn : String
  not_before : String
  not_after : String
  is_ca : Bool
  key_usage : KeyUsage
}

///|
pub struct TestPki {
  ca_priv : @sm2.PrivateKey
  ca_cert : Certificate
  server_sign_priv : @sm2.PrivateKey
  server_sign_cert : Certificate
  server_enc_priv : @sm2.PrivateKey
  server_enc_cert : Certificate
  client_sign_priv : @sm2.PrivateKey
  client_sign_cert : Certificate
  client_enc_priv : @sm2.PrivateKey
  client_enc_cert : Certificate
}

///|
fn write_sm2_sig_alg(w : @der.DerWriter) -> Unit raise @der.DerError {
  w.write_sequence(alg => alg.write_oid(@der.OID_SM2_SIGN_SM3))
}

///|
fn write_cn_name(w : @der.DerWriter, cn : String) -> Unit raise @der.DerError {
  w.write_sequence(name => {
    name.write_set(rdn => {
      rdn.write_sequence(atv => {
        atv.write_oid(@der.OID_COMMON_NAME)
        atv.write_utf8_string(cn)
      })
    })
  })
}

///|
fn write_time(w : @der.DerWriter, t : String) -> Unit raise @der.DerError {
  if t.length() == 15 {
    // GeneralizedTime YYYYMMDDHHMMSSZ
    let out = FixedArray::make(15, b'\x00')
    for i = 0; i < 15; i = i + 1 {
      out[i] = t[i].to_int().to_byte()
    }
    w.write_tlv(@der.TAG_GENERALIZED_TIME, Bytes::from_array(out)[:])
  } else {
    w.write_utc_time(t)
  }
}

///|
fn encode_key_usage_der(ku : KeyUsage) -> Bytes raise @der.DerError {
  let mut mask = 0
  if ku.digital_signature {
    mask = mask | 0x80
  }
  if ku.content_commitment {
    mask = mask | 0x40
  }
  if ku.key_encipherment {
    mask = mask | 0x20
  }
  if ku.data_encipherment {
    mask = mask | 0x10
  }
  if ku.key_agreement {
    mask = mask | 0x08
  }
  if ku.key_cert_sign {
    mask = mask | 0x04
  }
  if ku.crl_sign {
    mask = mask | 0x02
  }
  let w = @der.DerWriter::new()
  if mask == 0 {
    w.write_bit_string(b""[:], unused_bits=0)
  } else {
    // ITU-T X.690 §11.2.2 NamedBitList: strip all trailing zero bits.
    let mut unused = 0
    while unused < 7 && (mask & (1 << unused)) == 0 {
      unused = unused + 1
    }
    let byte_arr = FixedArray::make(1, mask.to_byte())
    w.write_bit_string(Bytes::from_array(byte_arr)[:], unused_bits=unused)
  }
  w.to_bytes()
}

///|
fn encode_basic_constraints_der(is_ca : Bool) -> Bytes {
  let w = @der.DerWriter::new()
  // Strict DER: cA DEFAULT FALSE must be omitted when false.
  w.write_sequence(seq => if is_ca { seq.write_boolean(true) })
  w.to_bytes()
}

///|
/// Build and SM2-sign a standards-compliant RFC 5280 / GM/T 0015 X.509 v3 certificate.
pub fn build_sm2_cert(
  spec : CertSpec,
  subject_pub : @sm2.PublicKey,
  issuer_priv : @sm2.PrivateKey,
) -> Certificate raise X509Error {
  if !subject_pub.is_valid() {
    raise InvalidPublicKey
  }
  let tbs_inner_bytes = try {
    let tbs = @der.DerWriter::new()
    // [0] EXPLICIT Version = v3 (2)
    tbs.write_context_explicit(0, ctx => ctx.write_int_u64(2UL))
    // serialNumber
    tbs.write_int_u64(spec.serial)
    // signature AlgorithmIdentifier (SM2-with-SM3)
    write_sm2_sig_alg(tbs)
    // issuer
    write_cn_name(tbs, spec.issuer_cn)
    // validity
    tbs.write_sequence(val => {
      write_time(val, spec.not_before)
      write_time(val, spec.not_after)
    })
    // subject
    write_cn_name(tbs, spec.subject_cn)
    // subjectPublicKeyInfo (id-ecPublicKey + sm2p256v1)
    let pub_uncompressed = subject_pub.to_uncompressed_bytes()
    tbs.write_sequence(spki => {
      spki.write_sequence(alg => {
        alg.write_oid(@der.OID_EC_PUBLIC_KEY)
        alg.write_oid(@der.OID_SM2_CURVE)
      })
      spki.write_bit_string(pub_uncompressed[:])
    })
    // [3] EXPLICIT extensions: BasicConstraints + KeyUsage
    let bc_der = encode_basic_constraints_der(spec.is_ca)
    let ku_der = encode_key_usage_der(spec.key_usage)
    tbs.write_context_explicit(3, ext_wrap => {
      ext_wrap.write_sequence(exts => {
        // BasicConstraints (critical = true)
        exts.write_sequence(ext => {
          ext.write_oid(@der.OID_BASIC_CONSTRAINTS)
          ext.write_boolean(true)
          ext.write_octet_string(bc_der[:])
        })
        // KeyUsage (critical = true)
        exts.write_sequence(ext => {
          ext.write_oid(@der.OID_KEY_USAGE)
          ext.write_boolean(true)
          ext.write_octet_string(ku_der[:])
        })
      })
    })
    tbs.to_bytes()
  } catch {
    e => raise map_der_err(e)
  }

  let tbs_full_w = @der.DerWriter::new()
  tbs_full_w.write_tlv(@der.TAG_SEQUENCE, tbs_inner_bytes[:])
  let tbs_der = tbs_full_w.to_bytes()

  let sig_der = @sm2.sign_der(issuer_priv, @sm2.DEFAULT_SM2_ID, tbs_der) catch {
    _ => raise InvalidSignature
  }

  let cert_der = try {
    let cert_w = @der.DerWriter::new()
    cert_w.write_sequence(c => {
      c.write_tlv(@der.TAG_SEQUENCE, tbs_inner_bytes[:])
      write_sm2_sig_alg(c)
      c.write_bit_string(sig_der[:])
    })
    cert_w.to_bytes()
  } catch {
    e => raise map_der_err(e)
  }
  Certificate::from_der(cert_der)
}

///|
fn concat_seed(prefix : Bytes, suffix : Bytes) -> Bytes {
  let out = FixedArray::make(prefix.length() + suffix.length(), b'\x00')
  for i = 0; i < prefix.length(); i = i + 1 {
    out[i] = prefix[i]
  }
  for i = 0; i < suffix.length(); i = i + 1 {
    out[prefix.length() + i] = suffix[i]
  }
  Bytes::from_array(out)
}

///|
fn derive_priv(
  prefix : Bytes,
  label : Bytes,
) -> @sm2.PrivateKey raise X509Error {
  @sm2.derive_keypair_from_seed(concat_seed(prefix, label)) catch {
    _ => raise InvalidPublicKey
  }
}

///|
/// Deterministically generate a complete TLCP dual-certificate test PKI:
/// Root CA + Server (sign & enc) + Client (sign & enc).
pub fn generate_test_pki(seed_prefix : Bytes) -> TestPki raise X509Error {
  let ca_cn = "MoonTLCP Test Root CA"
  let not_before = "260101000000Z"
  let not_after = "360101000000Z"

  let ca_ku : KeyUsage = {
    digital_signature: false,
    content_commitment: false,
    key_encipherment: false,
    data_encipherment: false,
    key_agreement: false,
    key_cert_sign: true,
    crl_sign: true,
  }
  let sign_ku : KeyUsage = {
    digital_signature: true,
    content_commitment: true,
    key_encipherment: false,
    data_encipherment: false,
    key_agreement: false,
    key_cert_sign: false,
    crl_sign: false,
  }
  let enc_ku : KeyUsage = {
    digital_signature: false,
    content_commitment: false,
    key_encipherment: true,
    data_encipherment: true,
    key_agreement: true,
    key_cert_sign: false,
    crl_sign: false,
  }

  let ca_priv = derive_priv(seed_prefix, b":ca")
  let ca_cert = build_sm2_cert(
    {
      serial: 1UL,
      subject_cn: ca_cn,
      issuer_cn: ca_cn,
      not_before,
      not_after,
      is_ca: true,
      key_usage: ca_ku,
    },
    ca_priv.public_key(),
    ca_priv,
  )

  let server_sign_priv = derive_priv(seed_prefix, b":server-sign")
  let server_sign_cert = build_sm2_cert(
    {
      serial: 2UL,
      subject_cn: "server.moontlcp.local",
      issuer_cn: ca_cn,
      not_before,
      not_after,
      is_ca: false,
      key_usage: sign_ku,
    },
    server_sign_priv.public_key(),
    ca_priv,
  )

  let server_enc_priv = derive_priv(seed_prefix, b":server-enc")
  let server_enc_cert = build_sm2_cert(
    {
      serial: 3UL,
      subject_cn: "server.moontlcp.local",
      issuer_cn: ca_cn,
      not_before,
      not_after,
      is_ca: false,
      key_usage: enc_ku,
    },
    server_enc_priv.public_key(),
    ca_priv,
  )

  let client_sign_priv = derive_priv(seed_prefix, b":client-sign")
  let client_sign_cert = build_sm2_cert(
    {
      serial: 4UL,
      subject_cn: "client.moontlcp.local",
      issuer_cn: ca_cn,
      not_before,
      not_after,
      is_ca: false,
      key_usage: sign_ku,
    },
    client_sign_priv.public_key(),
    ca_priv,
  )

  let client_enc_priv = derive_priv(seed_prefix, b":client-enc")
  let client_enc_cert = build_sm2_cert(
    {
      serial: 5UL,
      subject_cn: "client.moontlcp.local",
      issuer_cn: ca_cn,
      not_before,
      not_after,
      is_ca: false,
      key_usage: enc_ku,
    },
    client_enc_priv.public_key(),
    ca_priv,
  )

  {
    ca_priv,
    ca_cert,
    server_sign_priv,
    server_sign_cert,
    server_enc_priv,
    server_enc_cert,
    client_sign_priv,
    client_sign_cert,
    client_enc_priv,
    client_enc_cert,
  }
}
