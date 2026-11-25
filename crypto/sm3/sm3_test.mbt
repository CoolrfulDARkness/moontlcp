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
test "GB/T 32905 official SM3 test vectors" {
  // Vector 1: "abc"
  assert_eq(
    to_hex(@sm3.sm3(b"abc")),
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
  // Vector 2: 64-byte "abcd" * 16
  let v2 = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
  assert_eq(
    to_hex(@sm3.sm3(v2)),
    "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
  )
  // Empty string vector
  assert_eq(
    to_hex(@sm3.sm3(b"")),
    "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
  )
}

///|
test "SM3 streaming equals one-shot and clone preserves state" {
  let msg = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
  let h = @sm3.Sm3::new()
  h.update_view(msg[0:7])
  h.update_view(msg[7:55])
  let snap = h.clone()
  h.update_view(msg[55:64])
  assert_eq(to_hex(h.finalize()), to_hex(@sm3.sm3(msg)))
  // Verify snapshot was not mutated
  snap.update_view(msg[55:64])
  assert_eq(to_hex(snap.finalize()), to_hex(@sm3.sm3(msg)))
}

///|
test "HMAC-SM3 and TLCP PRF consistency" {
  let key = b"key"
  let data = b"The quick brown fox jumps over the lazy dog"
  let mac1 = @sm3.hmac_sm3(key, data)
  let mac2 = @sm3.hmac_sm3_parts(key, [data[0:10], data[10:]])
  assert_eq(mac1, mac2)
  assert_eq(mac1.length(), 32)
  // TLCP PRF determinism and prefix property
  let prf48 = @sm3.tlcp_prf(b"secret", b"master secret", b"seed1234", 48)
  let prf12 = @sm3.tlcp_prf(b"secret", b"master secret", b"seed1234", 12)
  assert_eq(prf48.length(), 48)
  assert_eq(prf12.length(), 12)
  for i = 0; i < 12; i = i + 1 {
    assert_eq(prf48[i], prf12[i])
  }
}
