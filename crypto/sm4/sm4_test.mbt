///|
fn from_hex(s : String) -> Bytes {
  let n = s.length() / 2
  let out = FixedArray::make(n, b'\x00')
  fn nibble(c : Int) -> Int {
    if c >= 48 && c <= 57 {
      c - 48
    } else if c >= 97 && c <= 102 {
      c - 87
    } else {
      c - 55
    }
  }
  for i = 0; i < n; i = i + 1 {
    let hi = nibble(s[i * 2].to_int())
    let lo = nibble(s[i * 2 + 1].to_int())
    out[i] = ((hi << 4) | lo).to_byte()
  }
  Bytes::from_array(out)
}

///|
fn to_hex(data : Bytes) -> String {
  let digits = "0123456789abcdef"
  let buf = StringBuilder()
  for i = 0; i < data.length(); i = i + 1 {
    let v = data[i].to_int()
    buf.write_char(digits[(v >> 4) & 0xF].to_int().unsafe_to_char())
    buf.write_char(digits[v & 0xF].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
test "GB/T 32907 official SM4 block test vectors (1-round and 1M-round)" {
  let key = from_hex("0123456789abcdeffedcba9876543210")
  let pt = from_hex("0123456789abcdeffedcba9876543210")
  let sm4 = @sm4.Sm4Key::new(key)
  let ct = sm4.encrypt_block(pt)
  assert_eq(to_hex(ct), "681edf34d206965e86b3e94f536e4246")
  assert_eq(sm4.decrypt_block(ct), pt)
  // 1,000,000 iterative encryptions (GB/T 32907 Appendix A.2)
  let buf = FixedArray::make(16, b'\x00')
  for i = 0; i < 16; i = i + 1 {
    buf[i] = pt[i]
  }
  for _i = 0; _i < 1000000; _i = _i + 1 {
    sm4.encrypt_block_inplace(buf, 0)
  }
  assert_eq(to_hex(Bytes::from_array(buf)), "595298c7c6fd271f0402f804c33d3f66")
}

///|
test "RFC 8998 Appendix A.1 official SM4-GCM test vector" {
  let key = from_hex("0123456789abcdeffedcba9876543210")
  let iv = from_hex("00001234567800000000abcd")
  let aad = from_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2")
  let pt = from_hex(
    "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa",
  )
  let sm4 = @sm4.Sm4Key::new(key)
  let (ct, tag) = sm4.gcm_encrypt(iv, aad, pt)
  assert_eq(
    to_hex(ct),
    "17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d",
  )
  assert_eq(to_hex(tag), "83de3541e4c2b58177e065a9bf7b62ec")
  let dec = sm4.gcm_decrypt(iv, aad, ct, tag)
  assert_eq(dec, pt)
  // Tampered tag must fail authentication
  let bad_tag = from_hex("83de3541e4c2b58177e065a9bf7b62ed")
  let failed = try {
    ignore(sm4.gcm_decrypt(iv, aad, ct, bad_tag))
    false
  } catch {
    @sm4.AuthFailed => true
    _ => false
  }
  assert_true(failed)
}

///|
test "SM4-CBC PKCS#7 round-trip and bad padding rejection" {
  let key = from_hex("0123456789abcdeffedcba9876543210")
  let iv = from_hex("000102030405060708090a0b0c0d0e0f")
  let sm4 = @sm4.Sm4Key::new(key)
  for msg in [b"", b"A", b"0123456789abcdef", b"GM/T 0024 TLCP 1.1 test payload!"] {
    let ct = sm4.cbc_encrypt_pkcs7(iv, msg)
    let pt = sm4.cbc_decrypt_pkcs7(iv, ct)
    assert_eq(pt, msg)
  }
  // Flip last byte to corrupt padding
  let ct = sm4.cbc_encrypt_pkcs7(iv, b"padding test")
  let bad = FixedArray::make(ct.length(), b'\x00')
  for i = 0; i < ct.length(); i = i + 1 {
    bad[i] = ct[i]
  }
  bad[bad.length() - 1] = (bad[bad.length() - 1].to_uint() ^ 0x01U).to_byte()
  let rejected = try {
    ignore(sm4.cbc_decrypt_pkcs7(iv, Bytes::from_array(bad)))
    false
  } catch {
    @sm4.InvalidPadding => true
    _ => false
  }
  assert_true(rejected)
}
