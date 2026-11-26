///|
test "reduce_ha40_mod_n_minus_1_plus_1 exact boundary arithmetic" {
  // ha = 0xFF * 40 mod (BN256_N - 1) + 1
  let n_bn256 = hex_to_bytes(
    "B640000002A3A6F1D603AB4FF58EC74449F2934B18EA8BEEE56EE19CD69ECF25",
  ).unwrap()
  let ha_max = Bytes::make(40, b'\xff')
  assert_eq(
    bytes_to_hex(reduce_ha40_mod_n_minus_1_plus_1(ha_max, n_bn256)),
    "3d3341b26ad6d031e43238c6840b1846b9c8cf71a0440b49a6d297052dc62aa8",
  )
  // ha = 2^64 - 1, n = 2^128 => r = 2^64 - 1, r + 1 = 2^64 (tests +1 limb carry)
  let n_2_128 = hex_to_bytes(
    "0000000000000000000000000000000100000000000000000000000000000000",
  ).unwrap()
  let ha_carry = hex_to_bytes(
    "0000000000000000000000000000000000000000000000000000000000000000ffffffffffffffff",
  ).unwrap()
  assert_eq(
    bytes_to_hex(reduce_ha40_mod_n_minus_1_plus_1(ha_carry, n_2_128)),
    "0000000000000000000000000000000000000000000000010000000000000000",
  )
  // ha = 0x04, n = 5 => (4 mod 4) + 1 = 1
  let n_5 = hex_to_bytes(
    "0000000000000000000000000000000000000000000000000000000000000005",
  ).unwrap()
  let ha_4 = hex_to_bytes(
    "00000000000000000000000000000000000000000000000000000000000000000000000000000004",
  ).unwrap()
  assert_eq(
    bytes_to_hex(reduce_ha40_mod_n_minus_1_plus_1(ha_4, n_5)),
    "0000000000000000000000000000000000000000000000000000000000000001",
  )
  // ha = 0x03, n = 5 => (3 mod 4) + 1 = 4
  let ha_3 = hex_to_bytes(
    "00000000000000000000000000000000000000000000000000000000000000000000000000000003",
  ).unwrap()
  assert_eq(
    bytes_to_hex(reduce_ha40_mod_n_minus_1_plus_1(ha_3, n_5)),
    "0000000000000000000000000000000000000000000000000000000000000004",
  )
}
