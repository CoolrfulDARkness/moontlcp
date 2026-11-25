///|
test "ct_eq and ct_eq_view" {
  let a = b"hello world"
  let b = b"hello world"
  let c = b"hello worlD"
  let d = b"hello"
  assert_true(@ct.ct_eq(a, b))
  assert_false(@ct.ct_eq(a, c))
  assert_false(@ct.ct_eq(a, d))
  assert_true(@ct.ct_eq_view(a[0:5], d[:]))
  assert_false(@ct.ct_eq_view(a[0:5], b"hellx"[:]))
}

///|
test "ct_select and comparisons" {
  assert_eq(@ct.ct_is_zero_u32(0U), 1U)
  assert_eq(@ct.ct_is_zero_u32(1U), 0U)
  assert_eq(@ct.ct_is_zero_u32(0x80000000U), 0U)
  assert_eq(@ct.ct_is_zero_u32(0xFFFFFFFFU), 0U)
  assert_eq(@ct.ct_eq_u32(42U, 42U), 1U)
  assert_eq(@ct.ct_eq_u32(42U, 43U), 0U)
  assert_eq(@ct.ct_lt_u32(5U, 10U), 1U)
  assert_eq(@ct.ct_lt_u32(10U, 10U), 0U)
  assert_eq(@ct.ct_lt_u32(10U, 5U), 0U)
  assert_eq(@ct.ct_lt_u32(0U, 0xFFFFFFFFU), 1U)
  assert_eq(@ct.ct_lt_u32(0xFFFFFFFFU, 0U), 0U)
  assert_eq(@ct.ct_select_u32(1U, 0xAABBCCDD, 0x11223344), 0xAABBCCDD)
  assert_eq(@ct.ct_select_u32(0U, 0xAABBCCDD, 0x11223344), 0x11223344)
  assert_eq(@ct.ct_select_byte(1U, b'\xAA', b'\x55'), b'\xAA')
  assert_eq(@ct.ct_select_byte(0U, b'\xAA', b'\x55'), b'\x55')
}

///|
test "zeroize clears buffer" {
  let buf : FixedArray[Byte] = FixedArray::make(8, b'\xFF')
  @ct.zeroize(buf)
  for i = 0; i < 8; i = i + 1 {
    assert_eq(buf[i], b'\x00')
  }
}
