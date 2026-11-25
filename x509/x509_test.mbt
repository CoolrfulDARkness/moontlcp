///|
fn[T] catch_x509(f : () -> T raise @x509.X509Error) -> @x509.X509Error? {
  try {
    ignore(f())
    None
  } catch {
    e => Some(e)
  }
}

///|
fn flip_byte_in_cert(raw : Bytes, idx : Int32) -> Bytes {
  let out = FixedArray::make(raw.length(), b'\x00')
  for i = 0; i < raw.length(); i = i + 1 {
    out[i] = if i == idx { (raw[i].to_int() ^ 0x01).to_byte() } else { raw[i] }
  }
  Bytes::from_array(out)
}

///|
test "generate_test_pki DER/PEM round-trip and dual-cert verification succeed" {
  let pki = @x509.generate_test_pki(b"moontlcp-test-seed-01")
  // Verify CA self-signature and metadata
  assert_true(pki.ca_cert.is_ca)
  assert_eq(pki.ca_cert.subject_cn, "MoonTLCP Test Root CA")
  assert_eq(pki.ca_cert.issuer_cn, "MoonTLCP Test Root CA")
  assert_eq(pki.ca_cert.signature_oid, @der.OID_SM2_SIGN_SM3)
  pki.ca_cert.verify_issued_by(pki.ca_cert)

  // Verify server & client certs directly against CA
  assert_true(!pki.server_sign_cert.is_ca)
  assert_true(!pki.server_enc_cert.is_ca)
  assert_eq(pki.server_sign_cert.public_key, pki.server_sign_priv.public_key())
  assert_eq(pki.server_enc_cert.public_key, pki.server_enc_priv.public_key())
  assert_eq(pki.client_sign_cert.public_key, pki.client_sign_priv.public_key())
  assert_eq(pki.client_enc_cert.public_key, pki.client_enc_priv.public_key())
  pki.server_sign_cert.verify_issued_by(pki.ca_cert)
  pki.server_enc_cert.verify_issued_by(pki.ca_cert)
  pki.client_sign_cert.verify_issued_by(pki.ca_cert)
  pki.client_enc_cert.verify_issued_by(pki.ca_cert)

  // PEM round-trip for multi-cert bundle (server sign + server enc + CA)
  let pem_bundle = pki.server_sign_cert.to_pem() +
    "\n" +
    pki.server_enc_cert.to_pem() +
    "\n" +
    pki.ca_cert.to_pem()
  let parsed = @x509.Certificate::from_pem(pem_bundle)
  assert_eq(parsed.length(), 3)
  assert_eq(parsed[0], pki.server_sign_cert)
  assert_eq(parsed[1], pki.server_enc_cert)
  assert_eq(parsed[2], pki.ca_cert)

  // TLCP dual-cert verification for server and client bundles
  let server_bundle = @x509.parse_and_verify_dual_certs(
    [pki.server_sign_cert.raw_der, pki.server_enc_cert.raw_der],
    [pki.ca_cert],
  )
  assert_eq(server_bundle.sign_cert, pki.server_sign_cert)
  assert_eq(server_bundle.enc_cert, pki.server_enc_cert)
  assert_eq(server_bundle.intermediates.length(), 0)

  let client_bundle = @x509.parse_and_verify_dual_certs(
    [pki.client_sign_cert.raw_der, pki.client_enc_cert.raw_der],
    [pki.ca_cert],
  )
  assert_eq(client_bundle.sign_cert, pki.client_sign_cert)
  assert_eq(client_bundle.enc_cert, pki.client_enc_cert)
}

///|
test "swapped dual certificates are strictly rejected" {
  let pki = @x509.generate_test_pki(b"swap-test")
  // Put encryption cert at [0] and signing cert at [1]
  let err = catch_x509(() => {
    @x509.parse_and_verify_dual_certs(
      [pki.server_enc_cert.raw_der, pki.server_sign_cert.raw_der],
      [pki.ca_cert],
    )
  })
  assert_true(err is Some(@x509.X509Error::DualCertMismatch(_)))

  // Put two signing certs -> enc_cert slot [1] fails with DualCertMismatch
  let err2 = catch_x509(() => {
    @x509.parse_and_verify_dual_certs(
      [pki.server_sign_cert.raw_der, pki.client_sign_cert.raw_der],
      [pki.ca_cert],
    )
  })
  assert_true(err2 is Some(@x509.X509Error::DualCertMismatch(_)))

  // Fewer than 2 certs rejected with InvalidCertCount
  let err3 = catch_x509(() => {
    @x509.parse_and_verify_dual_certs([pki.server_sign_cert.raw_der], [
      pki.ca_cert,
    ])
  })
  assert_true(err3 is Some(@x509.X509Error::InvalidCertCount(1)))
}

///|
test "tampering single byte in tbs_der fails SM2 signature verification" {
  let pki = @x509.generate_test_pki(b"tamper-test")
  let raw = pki.server_sign_cert.raw_der
  // Locate the UTF-8 byte 's' of "server.moontlcp.local" inside raw_der and flip 1 bit
  let mut target = -1
  for i = 0; i + 6 < raw.length(); i = i + 1 {
    if raw[i] == b's' &&
      raw[i + 1] == b'e' &&
      raw[i + 2] == b'r' &&
      raw[i + 3] == b'v' &&
      raw[i + 4] == b'e' &&
      raw[i + 5] == b'r' {
      target = i
      break
    }
  }
  assert_true(target >= 0)
  let tampered_der = flip_byte_in_cert(raw, target)
  let tampered_cert = @x509.Certificate::from_der(tampered_der)
  // Direct verify_issued_by must reject with InvalidSignature
  assert_true(
    catch_x509(() => tampered_cert.verify_issued_by(pki.ca_cert))
    is Some(@x509.X509Error::InvalidSignature),
  )
  // Dual-cert verification must also reject tampered cert
  assert_true(
    catch_x509(() => {
      @x509.parse_and_verify_dual_certs(
        [tampered_der, pki.server_enc_cert.raw_der],
        [pki.ca_cert],
      )
    })
    is Some(@x509.X509Error::InvalidSignature),
  )
}

///|
test "untrusted CA, empty trust_anchors, and non-CA issuer are rejected" {
  let pki_a = @x509.generate_test_pki(b"ca-alpha")
  let pki_b = @x509.generate_test_pki(b"ca-beta")

  // Empty trust_anchors -> fail-closed ChainVerificationFailed
  assert_true(
    catch_x509(() => {
      @x509.parse_and_verify_dual_certs(
        [pki_a.server_sign_cert.raw_der, pki_a.server_enc_cert.raw_der],
        [],
      )
    })
    is Some(@x509.X509Error::ChainVerificationFailed(_)),
  )

  // Certs issued by CA-A verified against untrusted CA-B (different key) -> rejected
  let rogue_ca_priv = @sm2.derive_keypair_from_seed(b"rogue-ca-other-cn")
  let rogue_ca = @x509.build_sm2_cert(
    {
      serial: 99UL,
      subject_cn: "Untrusted Root CA",
      issuer_cn: "Untrusted Root CA",
      not_before: "260101000000Z",
      not_after: "360101000000Z",
      is_ca: true,
      key_usage: {
        digital_signature: false,
        content_commitment: false,
        key_encipherment: false,
        data_encipherment: false,
        key_agreement: false,
        key_cert_sign: true,
        crl_sign: true,
      },
    },
    rogue_ca_priv.public_key(),
    rogue_ca_priv,
  )
  assert_true(
    catch_x509(() => {
      @x509.parse_and_verify_dual_certs(
        [pki_a.server_sign_cert.raw_der, pki_a.server_enc_cert.raw_der],
        [rogue_ca],
      )
    })
    is Some(@x509.X509Error::ChainVerificationFailed(_)),
  )
  // Same CN but different CA key (pki_b.ca_cert) -> InvalidSignature
  assert_true(
    catch_x509(() => {
      @x509.parse_and_verify_dual_certs(
        [pki_a.server_sign_cert.raw_der, pki_a.server_enc_cert.raw_der],
        [pki_b.ca_cert],
      )
    })
    is Some(@x509.X509Error::InvalidSignature),
  )

  // Non-CA leaf signing another cert must be rejected with NotCa
  let forged_leaf = @x509.build_sm2_cert(
    {
      serial: 77UL,
      subject_cn: "forged.local",
      issuer_cn: pki_a.server_sign_cert.subject_cn,
      not_before: "260101000000Z",
      not_after: "360101000000Z",
      is_ca: false,
      key_usage: {
        digital_signature: true,
        content_commitment: false,
        key_encipherment: false,
        data_encipherment: false,
        key_agreement: false,
        key_cert_sign: false,
        crl_sign: false,
      },
    },
    pki_b.server_sign_priv.public_key(),
    pki_a.server_sign_priv,
  )
  assert_true(
    catch_x509(() => forged_leaf.verify_issued_by(pki_a.server_sign_cert))
    is Some(@x509.X509Error::NotCa),
  )

  // CA with is_ca=true but missing keyCertSign must be rejected with BadKeyUsage
  let bad_ca_priv = @sm2.derive_keypair_from_seed(b"ca-no-keycertsign")
  let bad_ca = @x509.build_sm2_cert(
    {
      serial: 88UL,
      subject_cn: "Bad CA No KeyCertSign",
      issuer_cn: "Bad CA No KeyCertSign",
      not_before: "260101000000Z",
      not_after: "360101000000Z",
      is_ca: true,
      key_usage: {
        digital_signature: true,
        content_commitment: false,
        key_encipherment: false,
        data_encipherment: false,
        key_agreement: false,
        key_cert_sign: false,
        crl_sign: false,
      },
    },
    bad_ca_priv.public_key(),
    bad_ca_priv,
  )
  assert_true(
    catch_x509(() => bad_ca.verify_issued_by(bad_ca))
    is Some(@x509.X509Error::BadKeyUsage(_)),
  )
}

///|
test "3-tier intermediate CA chain verification and OpenSSL-style NULL alg param compatibility" {
  let root_priv = @sm2.derive_keypair_from_seed(b"chain-root")
  let inter_priv = @sm2.derive_keypair_from_seed(b"chain-inter")
  let sign_priv = @sm2.derive_keypair_from_seed(b"chain-sign")
  let enc_priv = @sm2.derive_keypair_from_seed(b"chain-enc")

  let ca_ku : @x509.KeyUsage = {
    digital_signature: false,
    content_commitment: false,
    key_encipherment: false,
    data_encipherment: false,
    key_agreement: false,
    key_cert_sign: true,
    crl_sign: true,
  }
  let root_ca = @x509.build_sm2_cert(
    {
      serial: 1UL,
      subject_cn: "Root GM CA",
      issuer_cn: "Root GM CA",
      not_before: "260101000000Z",
      not_after: "360101000000Z",
      is_ca: true,
      key_usage: ca_ku,
    },
    root_priv.public_key(),
    root_priv,
  )
  let inter_ca = @x509.build_sm2_cert(
    {
      serial: 2UL,
      subject_cn: "Intermediate GM CA",
      issuer_cn: "Root GM CA",
      not_before: "260101000000Z",
      not_after: "360101000000Z",
      is_ca: true,
      key_usage: ca_ku,
    },
    inter_priv.public_key(),
    root_priv,
  )
  let leaf_sign = @x509.build_sm2_cert(
    {
      serial: 3UL,
      subject_cn: "leaf.gm.local",
      issuer_cn: "Intermediate GM CA",
      not_before: "260101000000Z",
      not_after: "360101000000Z",
      is_ca: false,
      key_usage: {
        digital_signature: true,
        content_commitment: true,
        key_encipherment: false,
        data_encipherment: false,
        key_agreement: false,
        key_cert_sign: false,
        crl_sign: false,
      },
    },
    sign_priv.public_key(),
    inter_priv,
  )
  let leaf_enc = @x509.build_sm2_cert(
    {
      serial: 4UL,
      subject_cn: "leaf.gm.local",
      issuer_cn: "Intermediate GM CA",
      not_before: "260101000000Z",
      not_after: "360101000000Z",
      is_ca: false,
      key_usage: {
        digital_signature: false,
        content_commitment: false,
        key_encipherment: true,
        data_encipherment: false,
        key_agreement: false,
        key_cert_sign: false,
        crl_sign: false,
      },
    },
    enc_priv.public_key(),
    inter_priv,
  )

  let bundle = @x509.parse_and_verify_dual_certs(
    [leaf_sign.raw_der, leaf_enc.raw_der, inter_ca.raw_der],
    [root_ca],
  )
  assert_eq(bundle.sign_cert, leaf_sign)
  assert_eq(bundle.enc_cert, leaf_enc)
  assert_eq(bundle.intermediates.length(), 1)
  assert_eq(bundle.intermediates[0], inter_ca)
}

///|
test "OpenSSL-style multi-RDN, NULL alg param, non-critical extensions, and version/alg rejections" {
  // Build a realistic OpenSSL-like SM2 v3 cert with:
  // - AlgorithmIdentifier containing explicit NULL
  // - Multi-attribute DN (C=CN, O=GMSSL, CN=openssl.gm.cn)
  // - Non-critical SKI/AKI/EKU extensions alongside BasicConstraints & KeyUsage
  let ca_priv = @sm2.derive_keypair_from_seed(b"openssl-compat-ca")
  let ca_pub = ca_priv.public_key()
  let tbs_inner = @der.DerWriter::new()
  tbs_inner.write_context_explicit(0, ctx => ctx.write_int_u64(2UL))
  tbs_inner.write_int_u64(42UL)
  // SM2-with-SM3 with explicit NULL parameter
  tbs_inner.write_sequence(alg => {
    alg.write_oid(@der.OID_SM2_SIGN_SM3)
    alg.write_null()
  })
  // Multi-RDN issuer & subject
  let write_multi_dn = (w : @der.DerWriter) => {
    w.write_sequence(name => {
      name.write_set(s => {
        s.write_sequence(a => {
          a.write_oid(@der.OID_COUNTRY)
          a.write_printable_string("CN")
        })
      })
      name.write_set(s => {
        s.write_sequence(a => {
          a.write_oid(@der.OID_ORGANIZATION)
          a.write_utf8_string("国密测试机构")
        })
      })
      name.write_set(s => {
        s.write_sequence(a => {
          a.write_oid(@der.OID_COMMON_NAME)
          a.write_utf8_string("openssl.gm.cn")
        })
      })
    })
  }
  write_multi_dn(tbs_inner)
  tbs_inner.write_sequence(v => {
    v.write_utc_time("260101000000Z")
    v.write_tlv(@der.TAG_GENERALIZED_TIME, b"20500101000000Z"[:])
  })
  write_multi_dn(tbs_inner)
  let pub_bytes = ca_pub.to_uncompressed_bytes()
  tbs_inner.write_sequence(spki => {
    spki.write_sequence(alg => {
      alg.write_oid(@der.OID_EC_PUBLIC_KEY)
      alg.write_oid(@der.OID_SM2_CURVE)
    })
    spki.write_bit_string(pub_bytes[:])
  })
  tbs_inner.write_context_explicit(3, ext_wrap => {
    ext_wrap.write_sequence(exts => {
      // BasicConstraints CA=true with pathLenConstraint=1
      let bc = @der.DerWriter::new()
      bc.write_sequence(s => {
        s.write_boolean(true)
        s.write_int_u64(1UL)
      })
      exts.write_sequence(e => {
        e.write_oid(@der.OID_BASIC_CONSTRAINTS)
        e.write_boolean(true)
        e.write_octet_string(bc.to_bytes()[:])
      })
      // Non-critical SubjectKeyIdentifier (should be ignored cleanly)
      let ski = @der.DerWriter::new()
      ski.write_octet_string(b"\x01\x02\x03\x04"[:])
      exts.write_sequence(e => {
        e.write_oid(@der.OID_SUBJECT_KEY_ID)
        e.write_octet_string(ski.to_bytes()[:])
      })
      // KeyUsage: keyCertSign
      let ku = @der.DerWriter::new()
      ku.write_bit_string(b"\x04"[:], unused_bits=2)
      exts.write_sequence(e => {
        e.write_oid(@der.OID_KEY_USAGE)
        e.write_boolean(true)
        e.write_octet_string(ku.to_bytes()[:])
      })
    })
  })
  let tbs_inner_bytes = tbs_inner.to_bytes()
  let tbs_full_w = @der.DerWriter::new()
  tbs_full_w.write_tlv(@der.TAG_SEQUENCE, tbs_inner_bytes[:])
  let tbs_der = tbs_full_w.to_bytes()
  let sig = @sm2.sign_der(ca_priv, @sm2.DEFAULT_SM2_ID, tbs_der)
  let cert_w = @der.DerWriter::new()
  cert_w.write_sequence(c => {
    c.write_tlv(@der.TAG_SEQUENCE, tbs_inner_bytes[:])
    c.write_sequence(alg => {
      alg.write_oid(@der.OID_SM2_SIGN_SM3)
      alg.write_null()
    })
    c.write_bit_string(sig[:])
  })
  let parsed = @x509.Certificate::from_der(cert_w.to_bytes())
  assert_eq(parsed.subject_cn, "openssl.gm.cn")
  assert_eq(parsed.issuer_cn, "openssl.gm.cn")
  assert_eq(parsed.not_after, "20500101000000Z")
  assert_true(parsed.is_ca)
  parsed.verify_issued_by(parsed)

  // Reject v1 cert (omitted [0] version) with UnsupportedVersion
  let v1_w = @der.DerWriter::new()
  v1_w.write_sequence(c => {
    c.write_sequence(t => {
      t.write_int_u64(1UL)
      t.write_sequence(a => a.write_oid(@der.OID_SM2_SIGN_SM3))
    })
    c.write_sequence(a => a.write_oid(@der.OID_SM2_SIGN_SM3))
    c.write_bit_string(sig[:])
  })
  assert_true(
    catch_x509(() => @x509.Certificate::from_der(v1_w.to_bytes()))
    is Some(@x509.X509Error::UnsupportedVersion),
  )

  // Reject unsupported signature OID with UnsupportedAlgorithm
  let bad_alg_w = @der.DerWriter::new()
  bad_alg_w.write_sequence(c => {
    c.write_sequence(t => t.write_context_explicit(0, x => x.write_int_u64(2UL)))
    c.write_sequence(a => a.write_oid("1.2.840.10045.4.3.2")) // ecdsa-with-SHA256
    c.write_bit_string(sig[:])
  })
  assert_true(
    catch_x509(() => @x509.Certificate::from_der(bad_alg_w.to_bytes()))
    is Some(@x509.X509Error::UnsupportedAlgorithm("1.2.840.10045.4.3.2")),
  )
}
