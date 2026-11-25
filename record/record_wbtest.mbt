///|
test "sequence number overflow protection across Null, CBC, and GCM" {
  let enc_key = Bytes::make(16, b'\x11')
  let mac_key = Bytes::make(32, b'\x22')
  let imp_iv = Bytes::make(4, b'\x33')
  // 1. Null cipher: seq = MAX - 1 succeeds once, then MAX raises SequenceOverflow without wrapping
  let tx_null = RecordLayer::new()
  let rx_null = RecordLayer::new()
  tx_null.seq = 0xFFFFFFFFFFFFFFFEUL
  rx_null.seq = 0xFFFFFFFFFFFFFFFEUL
  let w_null = tx_null.seal(ApplicationData, b"last", b"")
  let (r_null, _) = decode_record(w_null[:])
  assert_eq(rx_null.open(r_null), b"last")
  assert_eq(tx_null.seq_num(), 0xFFFFFFFFFFFFFFFFUL)
  assert_eq(rx_null.seq_num(), 0xFFFFFFFFFFFFFFFFUL)
  let tx_null_overflow = try {
    ignore(tx_null.seal(ApplicationData, b"overflow", b""))
    false
  } catch {
    SequenceOverflow => true
    _ => false
  }
  assert_true(tx_null_overflow)
  assert_eq(tx_null.seq_num(), 0xFFFFFFFFFFFFFFFFUL)
  let rx_null_overflow = try {
    ignore(rx_null.open(r_null))
    false
  } catch {
    SequenceOverflow => true
    _ => false
  }
  assert_true(rx_null_overflow)
  assert_eq(rx_null.seq_num(), 0xFFFFFFFFFFFFFFFFUL)
  // 2. SM4-CBC-HMAC-SM3 sequence overflow
  let tx_cbc = RecordLayer::new()
  let rx_cbc = RecordLayer::new()
  tx_cbc.set_cipher(CipherState::new_cbc(enc_key, mac_key))
  rx_cbc.set_cipher(CipherState::new_cbc(enc_key, mac_key))
  tx_cbc.seq = 0xFFFFFFFFFFFFFFFEUL
  rx_cbc.seq = 0xFFFFFFFFFFFFFFFEUL
  let iv16 = Bytes::make(16, b'\x44')
  let w_cbc = tx_cbc.seal(ApplicationData, b"last-cbc", iv16)
  let (r_cbc, _) = decode_record(w_cbc[:])
  assert_eq(rx_cbc.open(r_cbc), b"last-cbc")
  assert_eq(tx_cbc.seq_num(), 0xFFFFFFFFFFFFFFFFUL)
  assert_eq(rx_cbc.seq_num(), 0xFFFFFFFFFFFFFFFFUL)
  let cbc_seal_ov = try {
    ignore(tx_cbc.seal(ApplicationData, b"x", iv16))
    false
  } catch {
    SequenceOverflow => true
    _ => false
  }
  assert_true(cbc_seal_ov)
  let cbc_open_ov = try {
    ignore(rx_cbc.open(r_cbc))
    false
  } catch {
    SequenceOverflow => true
    _ => false
  }
  assert_true(cbc_open_ov)
  // 3. SM4-GCM sequence overflow
  let tx_gcm = RecordLayer::new()
  let rx_gcm = RecordLayer::new()
  tx_gcm.set_cipher(CipherState::new_gcm(enc_key, imp_iv))
  rx_gcm.set_cipher(CipherState::new_gcm(enc_key, imp_iv))
  tx_gcm.seq = 0xFFFFFFFFFFFFFFFEUL
  rx_gcm.seq = 0xFFFFFFFFFFFFFFFEUL
  let iv8 = Bytes::make(8, b'\x55')
  let w_gcm = tx_gcm.seal(ApplicationData, b"last-gcm", iv8)
  let (r_gcm, _) = decode_record(w_gcm[:])
  assert_eq(rx_gcm.open(r_gcm), b"last-gcm")
  assert_eq(tx_gcm.seq_num(), 0xFFFFFFFFFFFFFFFFUL)
  assert_eq(rx_gcm.seq_num(), 0xFFFFFFFFFFFFFFFFUL)
  let gcm_seal_ov = try {
    ignore(tx_gcm.seal(ApplicationData, b"x", iv8))
    false
  } catch {
    SequenceOverflow => true
    _ => false
  }
  assert_true(gcm_seal_ov)
  let gcm_open_ov = try {
    ignore(rx_gcm.open(r_gcm))
    false
  } catch {
    SequenceOverflow => true
    _ => false
  }
  assert_true(gcm_open_ov)
}
