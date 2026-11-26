///|
fn from_hex(s : String) -> Bytes {
  let n = s.length() / 2
  let out = FixedArray::make(n, b'\x00')
  fn nibble(c : Int32) -> Int32 {
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
  for
    msg in [b"", b"A", b"0123456789abcdef", b"GM/T 0024 TLCP 1.1 test payload!"] {
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

///|
test "GB/T 38635.4 Appendix A.3 SM4-ECB-PKCS#7 official vector and boundary round-trips" {
  let k1 = from_hex("58373260f067ec48667c21c144f8bc33")
  let msg = b"Chinese IBE standard"
  let sm4_a3 = @sm4.Sm4Key::new(k1)
  let c2 = sm4_a3.ecb_encrypt_pkcs7(msg)
  assert_eq(c2.length(), 32)
  assert_eq(
    to_hex(c2),
    "e05b6fac6f11b965268c994f00dba7a8bb00fd60583546cbdf4649250863f10a",
  )
  assert_eq(sm4_a3.ecb_decrypt_pkcs7(c2), msg)
  // Boundary sweep 0..=48 bytes covering every pad length 1..=16 across 1..=4 blocks
  let key = from_hex("0123456789abcdeffedcba9876543210")
  let sm4 = @sm4.Sm4Key::new(key)
  let full_pad16 = Bytes::makei(16, fn(_) { b'\x10' })
  let ct_empty = sm4.ecb_encrypt_pkcs7(b"")
  assert_eq(ct_empty, sm4.encrypt_block(full_pad16))
  assert_eq(sm4.ecb_decrypt_pkcs7(ct_empty), b"")
  let block16 = from_hex("0123456789abcdeffedcba9876543210")
  let ct_16 = sm4.ecb_encrypt_pkcs7(block16)
  assert_eq(ct_16.length(), 32)
  assert_eq(to_hex(ct_16[0:16].to_owned()), "681edf34d206965e86b3e94f536e4246")
  assert_eq(ct_16[16:32].to_owned(), sm4.encrypt_block(full_pad16))
  assert_eq(sm4.ecb_decrypt_pkcs7(ct_16), block16)
  for len = 0; len <= 48; len = len + 1 {
    let pt = Bytes::makei(len, fn(i) { ((i * 37 + 11) & 0xFF).to_byte() })
    let ct = sm4.ecb_encrypt_pkcs7(pt)
    assert_eq(ct.length(), (len / 16 + 1) * 16)
    assert_eq(sm4.ecb_decrypt_pkcs7(ct), pt)
  }
}

///|
test "SM4-ECB-PKCS#7 adversarial length and padding tampering rejection" {
  let key = from_hex("58373260f067ec48667c21c144f8bc33")
  let sm4 = @sm4.Sm4Key::new(key)
  // Empty and non-multiple-of-16 lengths rejected with InvalidBlockLength
  for n in [0, 1, 15, 17, 31, 33] {
    let ct = Bytes::makei(n, fn(i) { i.to_byte() })
    let bad_len = try {
      ignore(sm4.ecb_decrypt_pkcs7(ct))
      false
    } catch {
      @sm4.InvalidBlockLength(_) => true
      _ => false
    }
    assert_true(bad_len)
  }
  // Crafted invalid pad bytes: 0x00, 0x11 (17), 0xff (255)
  let bad_blocks : Array[Bytes] = [
    Bytes::makei(16, fn(i) { if i < 15 { b'\x41' } else { b'\x00' } }),
    Bytes::makei(16, fn(_) { b'\x11' }),
    Bytes::makei(16, fn(_) { b'\xff' }),
  ]
  for blk in bad_blocks {
    let ct = sm4.encrypt_block(blk)
    let rej = try {
      ignore(sm4.ecb_decrypt_pkcs7(ct))
      false
    } catch {
      @sm4.InvalidPadding => true
      _ => false
    }
    assert_true(rej)
  }
  // Inconsistent padding bytes across all valid pad lengths 2..=16
  for pad = 2; pad <= 16; pad = pad + 1 {
    for corrupt_offset = 1
        corrupt_offset < pad
        corrupt_offset = corrupt_offset + 1 {
      let arr = FixedArray::make(16, b'\x41')
      for j = 16 - pad; j < 16; j = j + 1 {
        arr[j] = pad.to_byte()
      }
      arr[15 - corrupt_offset] = (pad ^ 1).to_byte()
      let ct = sm4.encrypt_block(Bytes::from_array(arr))
      let rej = try {
        ignore(sm4.ecb_decrypt_pkcs7(ct))
        false
      } catch {
        @sm4.InvalidPadding => true
        _ => false
      }
      assert_true(rej)
    }
  }
  // Bit-flip on GB/T 38635.4 A.3 ciphertext
  let valid_c2 = sm4.ecb_encrypt_pkcs7(b"Chinese IBE standard")
  let tampered = Bytes::makei(valid_c2.length(), fn(i) {
    if i == valid_c2.length() - 1 {
      (valid_c2[i].to_int() ^ 0x01).to_byte()
    } else {
      valid_c2[i]
    }
  })
  let flip_rej = try {
    ignore(sm4.ecb_decrypt_pkcs7(tampered))
    false
  } catch {
    @sm4.InvalidPadding => true
    _ => false
  }
  assert_true(flip_rej)
}
