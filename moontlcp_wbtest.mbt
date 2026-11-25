///|
/// Whitebox sanity check for root package helper invariants.
test "default_cipher_suites includes all 4 GM/T 0024-2023 cipher suites" {
  let suites = default_cipher_suites()
  assert_eq(suites.length(), 4)
  assert_eq(suites[0].to_u16(), 0xE053U)
  assert_eq(suites[1].to_u16(), 0xE013U)
  assert_eq(suites[2].to_u16(), 0xE051U)
  assert_eq(suites[3].to_u16(), 0xE011U)
}
