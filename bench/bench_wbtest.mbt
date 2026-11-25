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
