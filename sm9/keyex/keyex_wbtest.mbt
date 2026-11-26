///|
test "ResponderResult and InitiatorResult ct_eq detects single-field 1-bit differences" {
  let sk = Bytes::make(16, b'\xAA')
  let sk_diff = Bytes::makei(16, fn(i) {
    if i == 15 {
      b'\xAB'
    } else {
      b'\xAA'
    }
  })
  let sk_short = Bytes::make(15, b'\xAA')
  let tag1 = Bytes::make(32, b'\x11')
  let tag1_diff = Bytes::makei(32, fn(i) {
    if i == 31 {
      b'\x10'
    } else {
      b'\x11'
    }
  })
  let tag2 = Bytes::make(32, b'\x22')
  let tag2_diff = Bytes::makei(32, fn(i) {
    if i == 0 {
      b'\x23'
    } else {
      b'\x22'
    }
  })

  let r0 : ResponderResult = { sk, s_b: tag1, s_2: tag2, }
  assert_true(r0.ct_eq({ sk, s_b: tag1, s_2: tag2, }))
  assert_true(!r0.ct_eq({ sk: sk_diff, s_b: tag1, s_2: tag2, }))
  assert_true(!r0.ct_eq({ sk: sk_short, s_b: tag1, s_2: tag2, }))
  assert_true(!r0.ct_eq({ sk, s_b: tag1_diff, s_2: tag2, }))
  assert_true(!r0.ct_eq({ sk, s_b: tag1, s_2: tag2_diff, }))

  let i0 : InitiatorResult = { sk, s_a: tag1, s_1: tag2, }
  assert_true(i0.ct_eq({ sk, s_a: tag1, s_1: tag2, }))
  assert_true(!i0.ct_eq({ sk: sk_diff, s_a: tag1, s_1: tag2, }))
  assert_true(!i0.ct_eq({ sk: sk_short, s_a: tag1, s_1: tag2, }))
  assert_true(!i0.ct_eq({ sk, s_a: tag1_diff, s_1: tag2, }))
  assert_true(!i0.ct_eq({ sk, s_a: tag1, s_1: tag2_diff, }))
}
