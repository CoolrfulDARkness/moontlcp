///|
fn make_payload(len : Int32) -> Bytes {
  let buf = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    buf[i] = ((i * 131 + 17) & 0xFF).to_byte()
  }
  Bytes::from_array(buf)
}

///|
test "SM3 1KB" (b : @bench.T) {
  let data = make_payload(1024)
  b.bench(fn() { b.keep(@sm3.sm3(data)) })
}

///|
test "SM3 16KB" (b : @bench.T) {
  let data = make_payload(16384)
  b.bench(fn() { b.keep(@sm3.sm3(data)) })
}

///|
test "SM4-CBC encrypt 1KB" (b : @bench.T) {
  let key = @sm4.Sm4Key::new(make_payload(16))
  let iv = make_payload(16)
  let data = make_payload(1024)
  b.bench(fn() { b.keep(try! key.cbc_encrypt_pkcs7(iv, data)) })
}

///|
test "SM4-CBC encrypt 16KB" (b : @bench.T) {
  let key = @sm4.Sm4Key::new(make_payload(16))
  let iv = make_payload(16)
  let data = make_payload(16384)
  b.bench(fn() { b.keep(try! key.cbc_encrypt_pkcs7(iv, data)) })
}

///|
test "SM4-GCM encrypt 1KB" (b : @bench.T) {
  let key = @sm4.Sm4Key::new(make_payload(16))
  let nonce = make_payload(12)
  let aad = make_payload(13)
  let data = make_payload(1024)
  b.bench(fn() { b.keep(try! key.gcm_encrypt(nonce, aad, data)) })
}

///|
test "SM4-GCM encrypt 16KB" (b : @bench.T) {
  let key = @sm4.Sm4Key::new(make_payload(16))
  let nonce = make_payload(12)
  let aad = make_payload(13)
  let data = make_payload(16384)
  b.bench(fn() { b.keep(try! key.gcm_encrypt(nonce, aad, data)) })
}

///|
test "SM2 sign DER" (b : @bench.T) {
  let sk = @sm2.derive_keypair_from_seed(b"bench-sm2-sign-key")
  let msg = make_payload(64)
  b.bench(fn() { b.keep(try! @sm2.sign_der(sk, @sm2.DEFAULT_SM2_ID, msg)) })
}

///|
test "SM2 verify DER" (b : @bench.T) {
  let sk = @sm2.derive_keypair_from_seed(b"bench-sm2-verify-key")
  let pk = sk.public_key()
  let msg = make_payload(64)
  let sig = @sm2.sign_der(sk, @sm2.DEFAULT_SM2_ID, msg)
  b.bench(fn() { b.keep(@sm2.verify_der(pk, @sm2.DEFAULT_SM2_ID, msg, sig)) })
}

///|
test "SM2 ASN.1 encrypt 48B" (b : @bench.T) {
  let sk = @sm2.derive_keypair_from_seed(b"bench-sm2-enc-key")
  let pk = sk.public_key()
  let pms = make_payload(48)
  b.bench(fn() { b.keep(try! @sm2.encrypt_asn1(pk, pms, b"bench-enc-seed")) })
}

///|
test "SM2 ASN.1 decrypt 48B" (b : @bench.T) {
  let sk = @sm2.derive_keypair_from_seed(b"bench-sm2-dec-key")
  let pk = sk.public_key()
  let pms = make_payload(48)
  let ct = @sm2.encrypt_asn1(pk, pms, b"bench-dec-seed")
  b.bench(fn() { b.keep(try! @sm2.decrypt_asn1(sk, ct)) })
}

///|
test "SM2 key exchange (GB/T 32918.3)" (b : @bench.T) {
  let sk_a = @sm2.derive_keypair_from_seed(b"bench-ke-a")
  let eph_a = @sm2.derive_keypair_from_seed(b"bench-ke-eph-a")
  let sk_b = @sm2.derive_keypair_from_seed(b"bench-ke-b")
  let eph_b = @sm2.derive_keypair_from_seed(b"bench-ke-eph-b")
  let pk_b = sk_b.public_key()
  let eph_pk_b = eph_b.public_key()
  b.bench(fn() {
    b.keep(
      try! @sm2.key_exchange_initiator(
        @sm2.DEFAULT_SM2_ID,
        sk_a,
        eph_a,
        @sm2.DEFAULT_SM2_ID,
        pk_b,
        eph_pk_b,
        48,
      ),
    )
  })
}

///|
test "X.509 SM2 cert parse + verify" (b : @bench.T) {
  let pki = @x509.generate_test_pki(b"bench-pki-seed")
  let sign_der = pki.server_sign_cert.raw_der
  let ca_cert = pki.ca_cert
  b.bench(fn() {
    let cert = try! @x509.Certificate::from_der(sign_der)
    try! cert.verify_issued_by(ca_cert)
    b.keep(cert)
  })
}

///|
test "RecordLayer SM4-CBC-HMAC-SM3 seal+open 1KB" (b : @bench.T) {
  let enc_key = make_payload(16)
  let mac_key = make_payload(32)
  let iv = make_payload(16)
  let data = make_payload(1024)
  let writer = @record.RecordLayer::new()
  let reader = @record.RecordLayer::new()
  writer.set_cipher(@record.CipherState::new_cbc(enc_key, mac_key))
  reader.set_cipher(@record.CipherState::new_cbc(enc_key, mac_key))
  b.bench(fn() {
    let wire = try! writer.seal(@record.ContentType::ApplicationData, data, iv)
    let (rec, _) = try! @record.decode_record(wire[:])
    b.keep(try! reader.open(rec))
  })
}

///|
test "RecordLayer SM4-GCM seal+open 1KB" (b : @bench.T) {
  let enc_key = make_payload(16)
  let implicit_iv = make_payload(4)
  let explicit_nonce = make_payload(8)
  let data = make_payload(1024)
  let writer = @record.RecordLayer::new()
  let reader = @record.RecordLayer::new()
  writer.set_cipher(@record.CipherState::new_gcm(enc_key, implicit_iv))
  reader.set_cipher(@record.CipherState::new_gcm(enc_key, implicit_iv))
  b.bench(fn() {
    let wire = try! writer.seal(
      @record.ContentType::ApplicationData,
      data,
      explicit_nonce,
    )
    let (rec, _) = try! @record.decode_record(wire[:])
    b.keep(try! reader.open(rec))
  })
}

///|
fn bench_sm9_scalar(hex : String) -> @sm9_field.Fn {
  let bytes = match @sm9.hex_to_bytes(hex) {
    Some(b) => b
    None => abort("invalid SM9 bench hex")
  }
  match @sm9_field.Fn::from_be_bytes_nonzero(bytes) {
    Some(v) => v
    None => abort("invalid SM9 bench scalar")
  }
}

///|
test "SM9 BN256 R-ate pairing e(P2, P1)" (b : @bench.T) {
  let p1 = @sm9_ec.G1Affine::generator()
  let p2 = @sm9_ec.G2Affine::generator()
  b.bench(fn() { b.keep(@sm9.pair(p2, p1)) })
}

///|
test "SM9 G1 scalar mul" (b : @bench.T) {
  let p1 = @sm9_ec.G1Affine::generator()
  let k = bench_sm9_scalar(
    "291fe3cac8f58ad2dc462c8d4d578a94dafd5624ddc28e328d2936688a86cf1a",
  )
  b.bench(fn() { b.keep(p1.scalar_mul_fn(k)) })
}

///|
test "SM9 G2 scalar mul" (b : @bench.T) {
  let p2 = @sm9_ec.G2Affine::generator()
  let k = bench_sm9_scalar(
    "291fe3cac8f58ad2dc462c8d4d578a94dafd5624ddc28e328d2936688a86cf1a",
  )
  b.bench(fn() { b.keep(p2.scalar_mul_fn(k)) })
}

///|
test "SM9 sign (GB/T 38635.2)" (b : @bench.T) {
  let master = @sm9.sign_master_from_seed(b"bench-sign-master")
  let p_pub_s = master.public_key()
  let ds_a = match @sm9.extract_sign_key(master, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let msg = b"Chinese IBS standard"
  let r = bench_sm9_scalar(
    "00033c8616b06704813203dfd00965022ed15975c662337aed648835dc4b1cbe",
  )
  b.bench(fn() { b.keep(@sm9.sign_with_r(p_pub_s, ds_a, msg, r)) })
}

///|
test "SM9 verify (GB/T 38635.2)" (b : @bench.T) {
  let master = @sm9.sign_master_from_seed(b"bench-sign-master")
  let p_pub_s = master.public_key()
  let ds_a = match @sm9.extract_sign_key(master, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let msg = b"Chinese IBS standard"
  let sig = match @sm9.sign(p_pub_s, ds_a, msg) {
    Ok(s) => s
    Err(e) => abort(e)
  }
  b.bench(fn() { b.keep(@sm9.verify(p_pub_s, b"Alice", msg, sig)) })
}

///|
test "SM9 key exchange roundtrip (GB/T 38635.3)" (b : @bench.T) {
  let master = @sm9.enc_master_from_seed(b"bench-keyex-master")
  let p_pub_e = master.public_key()
  let de_a = match @sm9.extract_keyex_key(master, b"Alice") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let de_b = match @sm9.extract_keyex_key(master, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let r_a = bench_sm9_scalar(
    "00005879dd1d51e175946f23b1b41e93ba31c584ae59a426ec1046a4d03b06c8",
  )
  let r_b = bench_sm9_scalar(
    "00018b98c44bef9f8537fb7d071b2c928b3bc65bd3d69e1eee213564905634fe",
  )
  let ra_pt = match @sm9.keyex_ephemeral(p_pub_e, b"Bob", r_a) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  let rb_pt = match @sm9.keyex_ephemeral(p_pub_e, b"Alice", r_b) {
    Ok(pt) => pt
    Err(e) => abort(e)
  }
  b.bench(fn() {
    let resp = match
      @sm9.keyex_responder(
        p_pub_e, b"Alice", b"Bob", de_b, r_b, ra_pt, rb_pt, 16,
      ) {
      Ok(v) => v
      Err(e) => abort(e)
    }
    let init = match
      @sm9.keyex_initiator(
        p_pub_e,
        b"Alice",
        b"Bob",
        de_a,
        r_a,
        ra_pt,
        rb_pt,
        16,
        peer_s_b=resp.s_b,
      ) {
      Ok(v) => v
      Err(e) => abort(e)
    }
    b.keep(init)
  })
}

///|
test "SM9 KEM encap+decap (GB/T 38635.4)" (b : @bench.T) {
  let master = @sm9.enc_master_from_seed(b"bench-kem-master")
  let p_pub_e = master.public_key()
  let de_b = match @sm9.extract_enc_key(master, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let r = bench_sm9_scalar(
    "000074015f8489c01ef4270456f9e6475bfb602bde7f33fd482ab4e3684a6722",
  )
  b.bench(fn() {
    let encap = match @sm9.kem_encapsulate_with_r(p_pub_e, b"Bob", 32, r) {
      Ok(v) => v
      Err(e) => abort(e)
    }
    let decap = match @sm9.kem_decapsulate(b"Bob", de_b, encap.c1(), 32) {
      Ok(k) => k
      Err(e) => abort(e)
    }
    b.keep(decap)
  })
}

///|
test "SM9 PKE KDF-XOR encrypt+decrypt" (b : @bench.T) {
  let master = @sm9.enc_master_from_seed(b"bench-enc-master")
  let p_pub_e = master.public_key()
  let de_b = match @sm9.extract_enc_key(master, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let msg = b"Chinese IBE standard"
  let r = bench_sm9_scalar(
    "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )
  b.bench(fn() {
    let ct = match
      @sm9.encrypt_with_r(
        p_pub_e,
        b"Bob",
        msg,
        r,
        mode=@sm9_enc.EncMode::KdfXor,
      ) {
      Ok(c) => c
      Err(e) => abort(e)
    }
    let pt = match
      @sm9.decrypt(b"Bob", de_b, ct, mode=@sm9_enc.EncMode::KdfXor) {
      Ok(p) => p
      Err(e) => abort(e)
    }
    b.keep(pt)
  })
}

///|
test "SM9 PKE SM4-ECB-PKCS7 encrypt+decrypt" (b : @bench.T) {
  let master = @sm9.enc_master_from_seed(b"bench-enc-master")
  let p_pub_e = master.public_key()
  let de_b = match @sm9.extract_enc_key(master, b"Bob") {
    Ok(k) => k
    Err(e) => abort(e)
  }
  let msg = b"Chinese IBE standard"
  let r = bench_sm9_scalar(
    "0000aac0541779c8fc45e3e2cb25c12b5d2576b2129ae8bb5ee2cbe5ec9e785c",
  )
  b.bench(fn() {
    let ct = match
      @sm9.encrypt_with_r(
        p_pub_e,
        b"Bob",
        msg,
        r,
        mode=@sm9_enc.EncMode::Sm4EcbPkcs7,
      ) {
      Ok(c) => c
      Err(e) => abort(e)
    }
    let pt = match
      @sm9.decrypt(b"Bob", de_b, ct, mode=@sm9_enc.EncMode::Sm4EcbPkcs7) {
      Ok(p) => p
      Err(e) => abort(e)
    }
    b.keep(pt)
  })
}
