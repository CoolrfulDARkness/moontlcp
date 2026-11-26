///|
let bn256_n_hex : String = "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25"

///|
fn make_seq_bytes(len : Int32) -> Bytes {
  Bytes::makei(len, fn(i) { (i & 0xFF).to_byte() })
}

///|
test "SM3 standard vectors (GB/T 32905-2016 Appendix A & empty)" {
  // Appendix A Example 1: "abc"
  assert_eq(
    @hash.hash_hex(b"abc"),
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
  // Appendix A Example 2: "abcd" repeated 16 times (64 bytes)
  let abcd16 = b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
  assert_eq(
    @hash.hash_hex(abcd16),
    "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732",
  )
  // Empty input ""
  assert_eq(
    @hash.hash_hex(b""),
    "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
  )
}

///|
test "SM3 block boundary lengths (55, 56, 63, 64, 65, 119, 120, 128)" {
  let vectors : Array[(Int32, String)] = [
    (55, "a79cf9dcee3404abf7f769698201647fd9d3ff61d629d0f58bb4b5579a427db8"),
    (56, "62f7363b15f4de76dd925c493b9d6d00d4ba0ef2a1f334c1d0f13b293aeb40d1"),
    (63, "6165e4cbb15cde01c6226e0015a47f710f8f8e1f2c296700033bb34d9212109c"),
    (64, "93566f236d157aae078d1ddb5cebdbba1520b5142e22a8915564345ba2ae1d63"),
    (65, "c886e6814be748285a10b28ae62ddacd85db830cd2cf3a2bfa2f729c15f63618"),
    (119, "8f3ea392a89a7119982d6634660db1a95f35d68267a2235e3255998a857f4fbf"),
    (120, "6babee35e6a1515af9d6255109c24f3c08897829422c6225d235fd4c8527e9ec"),
    (128, "a9e7985473ca09df1510d83b572f72375430756c4a661b00724afeb8b75dd0a5"),
  ]
  for pair in vectors {
    let (len, expected) = pair
    let data = make_seq_bytes(len)
    assert_eq(@hash.hash_hex(data), expected)
  }
}

///|
test "SM3 streaming update, update_byte, finalize non-destructive, reset" {
  let msg = make_seq_bytes(197)
  let expected = @hash.hash(msg)
  // Chunk sizes: 1, 7, 13, 31, 64, 65
  let chunks : Array[Int32] = [1, 7, 13, 31, 64, 65]
  for chunk in chunks {
    let h = @hash.Sm3::new()
    let mut off = 0
    while off < msg.length() {
      let end = if off + chunk < msg.length() {
        off + chunk
      } else {
        msg.length()
      }
      h.update(msg[off:end])
      off = end
    }
    assert_eq(h.finalize(), expected)
    // Calling finalize twice yields the same digest
    assert_eq(h.finalize(), expected)
  }
  // Byte-by-byte update_byte + reset reuse
  let h = @hash.Sm3::new()
  for i = 0; i < msg.length(); i = i + 1 {
    h.update_byte(msg[i])
  }
  assert_eq(h.finalize(), expected)
  h.reset()
  h.update(b"abc")
  assert_eq(
    @hash.bytes_to_hex(h.finalize()),
    "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
  )
}

///|
test "KDF (GB/T 38635.1-2020) lengths 0, 16, 32, 48, 64 and negative" {
  assert_eq(@hash.kdf(b"abc", 0), b"")
  assert_eq(@hash.kdf(b"abc", -5), b"")
  assert_eq(
    @hash.bytes_to_hex(@hash.kdf(b"abc", 16)),
    "fe1ea80dac6f100c33537bd24619ec7c",
  )
  assert_eq(
    @hash.bytes_to_hex(@hash.kdf(b"abc", 32)),
    "fe1ea80dac6f100c33537bd24619ec7c72a1e8b1ffeaefb1eb52a37791fdaf61",
  )
  assert_eq(
    @hash.bytes_to_hex(@hash.kdf(b"abc", 48)),
    "fe1ea80dac6f100c33537bd24619ec7c72a1e8b1ffeaefb1eb52a37791fdaf619db16c0ac7bebb47238c6cc925ff66af",
  )
  assert_eq(
    @hash.bytes_to_hex(@hash.kdf(b"abc", 64)),
    "fe1ea80dac6f100c33537bd24619ec7c72a1e8b1ffeaefb1eb52a37791fdaf619db16c0ac7bebb47238c6cc925ff66af7936e278e12d2664502bb38b03fd41cb",
  )
}

///|
test "MAC(K2, C2) = SM3(C2 || K2) order check" {
  let digest = @hash.mac(b"key", b"cipher")
  assert_eq(
    @hash.bytes_to_hex(digest),
    "e53c18c4a0b2cda84748a033d069f728c7c8fd1a718086e0b00131591d463796",
  )
  // Confirm order is C2 || K2, not K2 || C2
  assert_eq(digest, @hash.hash(b"cipherkey"))
  assert_false(@hash.ct_eq_bytes(digest, @hash.hash(b"keycipher")))
}

///|
test "H1 / H2 and hv_bytes against Python BN256 reference vectors" {
  let n_be = @hash.hex_to_bytes(bn256_n_hex).unwrap()
  let alice_01 = b"Alice\x01"
  let bob_03 = b"Bob\x03"
  // hv_bytes non-positive length
  assert_eq(@hash.hv_bytes(b'\x01', alice_01, 0), b"")
  assert_eq(@hash.hv_bytes(b'\x01', alice_01, -1), b"")
  // 40-byte raw expansions
  assert_eq(
    @hash.bytes_to_hex(@hash.h1_hash40(alice_01)),
    "58f4f65afd95beb21170e7e5952f5de283fd26e5646df7a50a90fda3de6bc5866f06301ec10b5b4a",
  )
  assert_eq(
    @hash.bytes_to_hex(@hash.h1_hash40(bob_03)),
    "8795e170fb592de8bf5b2db4181e8ba7ee4a3e50281fe2ae0dfa3affe018a2c0617fddf42fb042a1",
  )
  assert_eq(
    @hash.bytes_to_hex(@hash.h2_hash40(alice_01)),
    "72eebc191e8ed589dadec0e485260eb9b84a68039e229f2689ca24e2758e91e2292fcc0e8e03bdbc",
  )
  // Reduced 32-byte scalars in [1, N - 1]
  assert_eq(
    @hash.bytes_to_hex(@hash.h1(alice_01, n_be)),
    "2acc468c3926b0bdb2767e99ff26e084de9ced8dbc7d5fbf418027b667862fab",
  )
  assert_eq(
    @hash.bytes_to_hex(@hash.h1(bob_03, n_be)),
    "9cb1f6288ce0e51043ce72344582ffc301e0a812a7f5f2004b85547a24b82716",
  )
  assert_eq(
    @hash.bytes_to_hex(@hash.h2(alice_01, n_be)),
    "a24d1807cbecd670c723da4646ab39e903574591d10cc65c8c54967d4200e6a1",
  )
  assert_eq(
    @hash.bytes_to_hex(@hash.h2(bob_03, n_be)),
    "7adfb599752b74c5cdc18bfafa84fb47cd7e00a3154e0d0221c52c26e79fe47a",
  )
  assert_eq(
    @hash.bytes_to_hex(@hash.h2(b"", n_be)),
    "1874f0970bf7221bd4a6358400851698920ecd08b9f8efab22eb7ddd9bfb8726",
  )
}

///|
test "H1 cross-limb order edge cases (2^64, 2^128, 2^192, 2^256-1, 2)" {
  let alice_01 = b"Alice\x01"
  let cases : Array[(String, String)] = [
    (
      "0000000000000000000000000000000000000000000000010000000000000000", "00000000000000000000000000000000000000000000000067fa32e896aa350b",
    ),
    (
      "0000000000000000000000000000000100000000000000000000000000000000", "000000000000000000000000000000001c01e589739b23694bf84d5f230f11a2",
    ),
    (
      "0000000000000001000000000000000000000000000000000000000000000000", "000000000000000083fd26e5646df7a56385f3fedc01843880771804563ab92d",
    ),
    (
      "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", "1170e7e5952f5de283fd26e5646df7a50a90fda3de6bc58720f01cd4bc36d8af",
    ),
    (
      "0000000000000000000000000000000000000000000000000000000000000002", "0000000000000000000000000000000000000000000000000000000000000001",
    ),
  ]
  for pair in cases {
    let (n_hex, expected) = pair
    let n_be = @hash.hex_to_bytes(n_hex).unwrap()
    assert_eq(@hash.bytes_to_hex(@hash.h1(alice_01, n_be)), expected)
  }
}

///|
test "ct_eq_bytes constant-time comparison" {
  assert_true(@hash.ct_eq_bytes(b"", b""))
  assert_true(@hash.ct_eq_bytes(b"sm9-test", b"sm9-test"))
  assert_false(@hash.ct_eq_bytes(b"sm9-test", b"sm9-tesu"))
  assert_false(@hash.ct_eq_bytes(b"sm9-test", b"tm9-test"))
  assert_false(@hash.ct_eq_bytes(b"sm9", b"sm9!"))
}

///|
test "hex_to_bytes and bytes_to_hex roundtrip and error handling" {
  assert_eq(@hash.hex_to_bytes(""), Some(b""))
  assert_eq(@hash.hex_to_bytes("   \t\r\n "), Some(b""))
  let mixed = "De Ad Be Ef 00 12 34 56 78 9a bc"
  let parsed = @hash.hex_to_bytes(mixed)
  assert_eq(parsed, Some(b"\xde\xad\xbe\xef\x00\x12\x34\x56\x78\x9a\xbc"))
  assert_eq(@hash.bytes_to_hex(parsed.unwrap()), "deadbeef00123456789abc")
  // Odd number of hex digits
  assert_eq(@hash.hex_to_bytes("a"), None)
  assert_eq(@hash.hex_to_bytes("a b c"), None)
  // Invalid characters
  assert_eq(@hash.hex_to_bytes("0x12"), None)
  assert_eq(@hash.hex_to_bytes("zz"), None)
  assert_eq(@hash.hex_to_bytes("12g4"), None)
}
