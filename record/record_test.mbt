///|
fn make_pattern_bytes(len : Int32, seed : Int32) -> Bytes {
  let buf = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    buf[i] = ((i * 31 + seed * 17 + 7) & 0xFF).to_byte()
  }
  Bytes::from_array(buf)
}

///|
fn flip_byte(data : Bytes, idx : Int32, mask : UInt32) -> Bytes {
  let buf = FixedArray::make(data.length(), b'\x00')
  for i = 0; i < data.length(); i = i + 1 {
    buf[i] = data[i]
  }
  buf[idx] = (buf[idx].to_uint() ^ mask).to_byte()
  Bytes::from_array(buf)
}

///|
fn concat_bytes(parts : Array[Bytes]) -> Bytes {
  let mut total = 0
  for i = 0; i < parts.length(); i = i + 1 {
    total = total + parts[i].length()
  }
  let out = FixedArray::make(total, b'\x00')
  let mut off = 0
  for i = 0; i < parts.length(); i = i + 1 {
    let p = parts[i]
    for j = 0; j < p.length(); j = j + 1 {
      out[off + j] = p[j]
    }
    off = off + p.length()
  }
  Bytes::from_array(out)
}

///|
fn build_tlcp_aad(
  seq : UInt64,
  ct : @record.ContentType,
  pt_len : Int32,
) -> Bytes {
  let aad = FixedArray::make(13, b'\x00')
  aad[0] = ((seq >> 56) & 0xFFUL).to_byte()
  aad[1] = ((seq >> 48) & 0xFFUL).to_byte()
  aad[2] = ((seq >> 40) & 0xFFUL).to_byte()
  aad[3] = ((seq >> 32) & 0xFFUL).to_byte()
  aad[4] = ((seq >> 24) & 0xFFUL).to_byte()
  aad[5] = ((seq >> 16) & 0xFFUL).to_byte()
  aad[6] = ((seq >> 8) & 0xFFUL).to_byte()
  aad[7] = (seq & 0xFFUL).to_byte()
  aad[8] = ct.to_byte()
  aad[9] = @record.TLCP_VERSION_MAJOR
  aad[10] = @record.TLCP_VERSION_MINOR
  aad[11] = ((pt_len >> 8) & 0xFF).to_byte()
  aad[12] = (pt_len & 0xFF).to_byte()
  Bytes::from_array(aad)
}

///|
test "TLCP 1.1 constants and ContentType conversions" {
  assert_eq(@record.TLCP_VERSION_MAJOR, b'\x01')
  assert_eq(@record.TLCP_VERSION_MINOR, b'\x01')
  assert_eq(@record.TLCP_VERSION_U16, 0x0101U)
  assert_eq(@record.RECORD_HEADER_LEN, 5)
  assert_eq(@record.MAX_PLAINTEXT_LEN, 16384)
  assert_eq(@record.MAX_CIPHERTEXT_LEN, 18432)
  let pairs : Array[(@record.ContentType, Byte)] = [
    (@record.ChangeCipherSpec, b'\x14'),
    (@record.Alert, b'\x15'),
    (@record.Handshake, b'\x16'),
    (@record.ApplicationData, b'\x17'),
  ]
  for pair in pairs {
    let (ct, byte_val) = pair
    assert_eq(ct.to_byte(), byte_val)
    assert_eq(@record.ContentType::from_byte(byte_val), ct)
  }
  for bad in [b'\x00', b'\x13', b'\x18', b'\xff'] {
    let err_ok = try {
      ignore(@record.ContentType::from_byte(bad))
      false
    } catch {
      @record.InvalidContentType(b) => b == bad
      _ => false
    }
    assert_true(err_ok)
  }
}

///|
test "record framing encode/decode, stream parsing, and Incomplete half-packets" {
  let rec1 = @record.RawRecord::{
    content_type: @record.Handshake,
    version_major: @record.TLCP_VERSION_MAJOR,
    version_minor: @record.TLCP_VERSION_MINOR,
    payload: b"hello tlcp",
  }
  let rec2 = @record.RawRecord::{
    content_type: @record.ApplicationData,
    version_major: @record.TLCP_VERSION_MAJOR,
    version_minor: @record.TLCP_VERSION_MINOR,
    payload: b"",
  }
  let w1 = @record.encode_record(rec1)
  assert_eq(w1.length(), 5 + 10)
  assert_eq(w1[0], b'\x16')
  assert_eq(w1[1], b'\x01')
  assert_eq(w1[2], b'\x01')
  assert_eq(w1[3], b'\x00')
  assert_eq(w1[4], b'\x0a')
  let w2 = @record.encode_record(rec2)
  assert_eq(w2.length(), 5)
  let stream = concat_bytes([w1, w2])
  let (d1, n1) = @record.decode_record(stream[:])
  assert_eq(d1, rec1)
  assert_eq(n1, w1.length())
  let (d2, n2) = @record.decode_record(stream[n1:])
  assert_eq(d2, rec2)
  assert_eq(n2, w2.length())
  // Every strict prefix of w1 must raise Incomplete
  for cut = 0; cut < w1.length(); cut = cut + 1 {
    let is_incomplete = try {
      ignore(@record.decode_record(w1[:cut]))
      false
    } catch {
      @record.Incomplete => true
      _ => false
    }
    assert_true(is_incomplete)
  }
}

///|
test "record framing rejects version downgrade and oversized records" {
  // Downgrade / unsupported versions: TLS 1.2 (0x0303), TLCP 1.0 (0x0100), TLS 1.0 (0x0301), future (0x0102)
  let bad_versions : Array[(Byte, Byte)] = [
    (b'\x03', b'\x03'),
    (b'\x01', b'\x00'),
    (b'\x03', b'\x01'),
    (b'\x01', b'\x02'),
  ]
  for v in bad_versions {
    let (maj, min) = v
    // Even with truncated payload, header version check must immediately reject
    let hdr = Bytes::from_array([b'\x16', maj, min, b'\x00', b'\x10'])
    let rejected = try {
      ignore(@record.decode_record(hdr[:]))
      false
    } catch {
      @record.UnsupportedVersion(m1, m2) => m1 == maj && m2 == min
      _ => false
    }
    assert_true(rejected)
  }
  // Exact boundary MAX_CIPHERTEXT_LEN (18432 = 0x4800) must succeed
  let max_payload = make_pattern_bytes(@record.MAX_CIPHERTEXT_LEN, 1)
  let max_rec = @record.RawRecord::{
    content_type: @record.ApplicationData,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: max_payload,
  }
  let encoded_max = @record.encode_record(max_rec)
  let (decoded_max, consumed_max) = @record.decode_record(encoded_max[:])
  assert_eq(decoded_max, max_rec)
  assert_eq(
    consumed_max,
    @record.RECORD_HEADER_LEN + @record.MAX_CIPHERTEXT_LEN,
  )
  // Oversized encode (18433 bytes) must raise RecordOverflow
  let over_rec = @record.RawRecord::{
    content_type: @record.ApplicationData,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: Bytes::make(@record.MAX_CIPHERTEXT_LEN + 1, b'\xaa'),
  }
  let enc_overflow = try {
    ignore(@record.encode_record(over_rec))
    false
  } catch {
    @record.RecordOverflow(n) => n == @record.MAX_CIPHERTEXT_LEN + 1
    _ => false
  }
  assert_true(enc_overflow)
  // Oversized decode header (18433 = 0x4801) must immediately raise RecordOverflow
  let over_hdr = Bytes::from_array([b'\x17', b'\x01', b'\x01', b'\x48', b'\x01'])
  let dec_overflow = try {
    ignore(@record.decode_record(over_hdr[:]))
    false
  } catch {
    @record.RecordOverflow(n) => n == 18433
    _ => false
  }
  assert_true(dec_overflow)
}

///|
test "16KB plaintext fragmentation and encrypted reassembly" {
  // Empty data produces 1 empty fragment
  let empty_frags = @record.fragment_plaintext(@record.ApplicationData, b"")
  assert_eq(empty_frags.length(), 1)
  assert_eq(empty_frags[0].payload, b"")
  // Exact 16384 boundary produces 1 fragment
  let exact = make_pattern_bytes(16384, 2)
  let exact_frags = @record.fragment_plaintext(@record.Handshake, exact)
  assert_eq(exact_frags.length(), 1)
  assert_eq(exact_frags[0].payload, exact)
  // 40000 bytes -> 16384 + 16384 + 7232 = 3 fragments, round-tripped through SM4-GCM
  let large = make_pattern_bytes(40000, 3)
  let frags = @record.fragment_plaintext(@record.ApplicationData, large)
  assert_eq(frags.length(), 3)
  assert_eq(frags[0].payload.length(), 16384)
  assert_eq(frags[1].payload.length(), 16384)
  assert_eq(frags[2].payload.length(), 7232)
  let key = make_pattern_bytes(16, 10)
  let imp_iv = make_pattern_bytes(4, 11)
  let sender = @record.RecordLayer::new()
  let receiver = @record.RecordLayer::new()
  sender.set_cipher(@record.CipherState::new_gcm(key, imp_iv))
  receiver.set_cipher(@record.CipherState::new_gcm(key, imp_iv))
  let wire_chunks : Array[Bytes] = []
  for i = 0; i < frags.length(); i = i + 1 {
    let exp_nonce = make_pattern_bytes(8, 20 + i)
    wire_chunks.push(
      sender.seal(frags[i].content_type, frags[i].payload, exp_nonce),
    )
  }
  assert_eq(sender.seq_num(), 3UL)
  let wire_stream = concat_bytes(wire_chunks)
  let reassembled : Array[Bytes] = []
  let mut off = 0
  while off < wire_stream.length() {
    let (raw, used) = @record.decode_record(wire_stream[off:])
    reassembled.push(receiver.open(raw))
    off = off + used
  }
  assert_eq(receiver.seq_num(), 3UL)
  assert_eq(concat_bytes(reassembled), large)
}

///|
test "Null cipher round-trip, seq tracking, set_cipher reset, and open validation" {
  let tx = @record.RecordLayer::new()
  let rx = @record.RecordLayer::new()
  assert_eq(tx.seq_num(), 0UL)
  assert_eq(rx.seq_num(), 0UL)
  for i = 0; i < 3; i = i + 1 {
    let msg = make_pattern_bytes(10 + i, i)
    let wire = tx.seal(@record.Handshake, msg, b"")
    let (raw, used) = @record.decode_record(wire[:])
    assert_eq(used, wire.length())
    let pt = rx.open(raw)
    assert_eq(pt, msg)
  }
  assert_eq(tx.seq_num(), 3UL)
  assert_eq(rx.seq_num(), 3UL)
  // Switching cipher resets seq to 0
  tx.set_cipher(@record.CipherState::null())
  rx.set_cipher(@record.CipherState::null())
  assert_eq(tx.seq_num(), 0UL)
  assert_eq(rx.seq_num(), 0UL)
  // seal rejects > 16384 plaintext without incrementing seq
  let over_pt = Bytes::make(@record.MAX_PLAINTEXT_LEN + 1, b'\x01')
  let seal_over = try {
    ignore(tx.seal(@record.ApplicationData, over_pt, b""))
    false
  } catch {
    @record.RecordOverflow(n) => n == @record.MAX_PLAINTEXT_LEN + 1
    _ => false
  }
  assert_true(seal_over)
  assert_eq(tx.seq_num(), 0UL)
  // open rejects > 16384 in Null mode and non-0x0101 version without incrementing seq
  let bad_ver_rec = @record.RawRecord::{
    content_type: @record.Handshake,
    version_major: b'\x03',
    version_minor: b'\x03',
    payload: b"abc",
  }
  let open_bad_ver = try {
    ignore(rx.open(bad_ver_rec))
    false
  } catch {
    @record.UnsupportedVersion(b'\x03', b'\x03') => true
    _ => false
  }
  assert_true(open_bad_ver)
  assert_eq(rx.seq_num(), 0UL)
  let over_null_rec = @record.RawRecord::{
    content_type: @record.ApplicationData,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: over_pt,
  }
  let open_over = try {
    ignore(rx.open(over_null_rec))
    false
  } catch {
    @record.RecordOverflow(n) => n == @record.MAX_PLAINTEXT_LEN + 1
    _ => false
  }
  assert_true(open_over)
  assert_eq(rx.seq_num(), 0UL)
}

///|
test "SM4-CBC-HMAC-SM3 round-trip across all block alignments and max 16KB plaintext" {
  let enc_key = make_pattern_bytes(16, 100)
  let mac_key = make_pattern_bytes(32, 101)
  let tx = @record.RecordLayer::new()
  let rx = @record.RecordLayer::new()
  tx.set_cipher(@record.CipherState::new_cbc(enc_key, mac_key))
  rx.set_cipher(@record.CipherState::new_cbc(enc_key, mac_key))
  let lengths = [
    0, 1, 2, 14, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 128, 255, 256, 16384,
  ]
  let cts : Array[@record.ContentType] = [
    @record.ChangeCipherSpec,
    @record.Alert,
    @record.Handshake,
    @record.ApplicationData,
  ]
  for i = 0; i < lengths.length(); i = i + 1 {
    let pt = make_pattern_bytes(lengths[i], 200 + i)
    let iv = make_pattern_bytes(16, 300 + i)
    let ct = cts[i % cts.length()]
    let wire = tx.seal(ct, pt, iv)
    let (raw, used) = @record.decode_record(wire[:])
    assert_eq(used, wire.length())
    assert_eq(raw.content_type, ct)
    // Verify CBC payload is 16B explicit IV + block-aligned ciphertext >= 48B
    assert_true(raw.payload.length() >= 64)
    assert_eq((raw.payload.length() - 16) % 16, 0)
    let dec = rx.open(raw)
    assert_eq(dec, pt)
    assert_eq(tx.seq_num(), (i + 1).to_uint64())
    assert_eq(rx.seq_num(), (i + 1).to_uint64())
  }
}

///|
test "SM4-CBC-HMAC-SM3 accepts valid multi-block TLS padding up to 255" {
  let enc_key = make_pattern_bytes(16, 40)
  let mac_key = make_pattern_bytes(32, 41)
  let sm4 = @sm4.Sm4Key::new(enc_key)
  let rx = @record.RecordLayer::new()
  rx.set_cipher(@record.CipherState::new_cbc(enc_key, mac_key))
  // Test pad_len = 31 (32 padding bytes) with pt_len = 0 -> 0 + 32 + 32 = 64B
  // and pad_len = 255 (256 padding bytes) with pt_len = 16 -> 16 + 32 + 256 = 304B
  let cases : Array[(Bytes, Int32)] = [
    (b"", 31),
    (make_pattern_bytes(16, 42), 255),
  ]
  for idx = 0; idx < cases.length(); idx = idx + 1 {
    let (pt, pad_len) = cases[idx]
    let seq = idx.to_uint64()
    let aad = build_tlcp_aad(seq, @record.ApplicationData, pt.length())
    let mac = @sm3.hmac_sm3_parts(mac_key, [aad[:], pt[:]])
    let total_pad = pad_len + 1
    let padded = FixedArray::make(
      pt.length() + mac.length() + total_pad,
      pad_len.to_byte(),
    )
    for i = 0; i < pt.length(); i = i + 1 {
      padded[i] = pt[i]
    }
    for i = 0; i < mac.length(); i = i + 1 {
      padded[pt.length() + i] = mac[i]
    }
    let iv = make_pattern_bytes(16, 50 + idx)
    let ct = sm4.cbc_encrypt_raw(iv, Bytes::from_array(padded))
    let rec = @record.RawRecord::{
      content_type: @record.ApplicationData,
      version_major: b'\x01',
      version_minor: b'\x01',
      payload: concat_bytes([iv, ct]),
    }
    assert_eq(rx.open(rec), pt)
    assert_eq(rx.seq_num(), seq + 1UL)
  }
}

///|
test "SM4-CBC-HMAC-SM3 tamper, padding oracle, and replay/desync uniformly return BadRecordMac" {
  let enc_key = make_pattern_bytes(16, 60)
  let mac_key = make_pattern_bytes(32, 61)
  let sm4 = @sm4.Sm4Key::new(enc_key)
  let tx = @record.RecordLayer::new()
  let rx = @record.RecordLayer::new()
  tx.set_cipher(@record.CipherState::new_cbc(enc_key, mac_key))
  rx.set_cipher(@record.CipherState::new_cbc(enc_key, mac_key))
  let pt0 = b"TLCP SM4-CBC anti-padding-oracle record 0"
  let iv0 = make_pattern_bytes(16, 62)
  let wire0 = tx.seal(@record.ApplicationData, pt0, iv0)
  let (rec0, _) = @record.decode_record(wire0[:])
  let pt1 = b"TLCP SM4-CBC record 1"
  let iv1 = make_pattern_bytes(16, 63)
  let wire1 = tx.seal(@record.ApplicationData, pt1, iv1)
  let (rec1, _) = @record.decode_record(wire1[:])
  // 1. Out-of-order / desynced sequence (sending rec1 when rx expects seq=0)
  let desync_bad = try {
    ignore(rx.open(rec1))
    false
  } catch {
    @record.BadRecordMac => true
    _ => false
  }
  assert_true(desync_bad)
  assert_eq(rx.seq_num(), 0UL)
  // 2. Flip bit in explicit IV, ciphertext body, and last block (padding)
  let tamper_offsets = [0, 15, 16, 32, rec0.payload.length() - 1]
  for off in tamper_offsets {
    let bad_rec = @record.RawRecord::{
      content_type: rec0.content_type,
      version_major: rec0.version_major,
      version_minor: rec0.version_minor,
      payload: flip_byte(rec0.payload, off, 0x01U),
    }
    let rejected = try {
      ignore(rx.open(bad_rec))
      false
    } catch {
      @record.BadRecordMac => true
      _ => false
    }
    assert_true(rejected)
    assert_eq(rx.seq_num(), 0UL)
  }
  // 3. Cross-content-type tampering
  let bad_ct_rec = @record.RawRecord::{
    content_type: @record.Handshake,
    version_major: rec0.version_major,
    version_minor: rec0.version_minor,
    payload: rec0.payload,
  }
  let ct_rejected = try {
    ignore(rx.open(bad_ct_rec))
    false
  } catch {
    @record.BadRecordMac => true
    _ => false
  }
  assert_true(ct_rejected)
  assert_eq(rx.seq_num(), 0UL)
  // 4. Directly crafted CBC record with valid MAC but 1 corrupted interior padding byte
  let aad0 = build_tlcp_aad(0UL, @record.ApplicationData, 0)
  let mac0 = @sm3.hmac_sm3_parts(mac_key, [aad0[:]])
  let bad_pad_buf = FixedArray::make(48, b'\x0f')
  for i = 0; i < 32; i = i + 1 {
    bad_pad_buf[i] = mac0[i]
  }
  bad_pad_buf[35] = b'\x0e' // Corrupt an interior padding byte while last byte stays 0x0f
  let bad_pad_ct = sm4.cbc_encrypt_raw(iv0, Bytes::from_array(bad_pad_buf))
  let bad_pad_rec = @record.RawRecord::{
    content_type: @record.ApplicationData,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: concat_bytes([iv0, bad_pad_ct]),
  }
  let pad_rejected = try {
    ignore(rx.open(bad_pad_rec))
    false
  } catch {
    @record.BadRecordMac => true
    _ => false
  }
  assert_true(pad_rejected)
  assert_eq(rx.seq_num(), 0UL)
  // 5. Directly crafted CBC record with pad_len=255 exceeding 48B buffer
  let huge_pad_buf = FixedArray::make(48, b'\xff')
  let huge_pad_ct = sm4.cbc_encrypt_raw(iv0, Bytes::from_array(huge_pad_buf))
  let huge_pad_rec = @record.RawRecord::{
    content_type: @record.ApplicationData,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: concat_bytes([iv0, huge_pad_ct]),
  }
  let huge_pad_rejected = try {
    ignore(rx.open(huge_pad_rec))
    false
  } catch {
    @record.BadRecordMac => true
    _ => false
  }
  assert_true(huge_pad_rejected)
  assert_eq(rx.seq_num(), 0UL)
  // 6. Truncated and non-block-aligned CBC payloads
  for bad_len in [0, 16, 48, 63, 65] {
    let short_rec = @record.RawRecord::{
      content_type: @record.ApplicationData,
      version_major: b'\x01',
      version_minor: b'\x01',
      payload: Bytes::make(bad_len, b'\x00'),
    }
    let short_rejected = try {
      ignore(rx.open(short_rec))
      false
    } catch {
      @record.BadRecordMac => true
      _ => false
    }
    assert_true(short_rejected)
    assert_eq(rx.seq_num(), 0UL)
  }
  // 7. Because failed opens never advance seq, legitimate rec0 and rec1 still succeed!
  assert_eq(rx.open(rec0), pt0)
  assert_eq(rx.seq_num(), 1UL)
  // 8. Replaying rec0 at seq=1 must fail with BadRecordMac
  let replay_rejected = try {
    ignore(rx.open(rec0))
    false
  } catch {
    @record.BadRecordMac => true
    _ => false
  }
  assert_true(replay_rejected)
  assert_eq(rx.seq_num(), 1UL)
  assert_eq(rx.open(rec1), pt1)
  assert_eq(rx.seq_num(), 2UL)
}

///|
test "SM4-GCM AEAD round-trip, tampering, and replay/desync rejection" {
  let enc_key = make_pattern_bytes(16, 70)
  let imp_iv = make_pattern_bytes(4, 71)
  let tx = @record.RecordLayer::new()
  let rx = @record.RecordLayer::new()
  tx.set_cipher(@record.CipherState::new_gcm(enc_key, imp_iv))
  rx.set_cipher(@record.CipherState::new_gcm(enc_key, imp_iv))
  let lengths = [0, 1, 15, 16, 17, 64, 512, 16384]
  for i = 0; i < lengths.length(); i = i + 1 {
    let pt = make_pattern_bytes(lengths[i], 80 + i)
    let nonce_exp = make_pattern_bytes(8, 90 + i)
    let wire = tx.seal(@record.ApplicationData, pt, nonce_exp)
    let (raw, used) = @record.decode_record(wire[:])
    assert_eq(used, wire.length())
    assert_eq(raw.payload.length(), 8 + lengths[i] + 16)
    assert_eq(rx.open(raw), pt)
  }
  assert_eq(tx.seq_num(), lengths.length().to_uint64())
  assert_eq(rx.seq_num(), lengths.length().to_uint64())
  // Produce two more records for tamper/replay tests
  let pt_a = b"GCM authenticated payload A"
  let wire_a = tx.seal(@record.Handshake, pt_a, make_pattern_bytes(8, 120))
  let (rec_a, _) = @record.decode_record(wire_a[:])
  let pt_b = b"GCM authenticated payload B"
  let wire_b = tx.seal(@record.Handshake, pt_b, make_pattern_bytes(8, 121))
  let (rec_b, _) = @record.decode_record(wire_b[:])
  let seq_before = rx.seq_num()
  // Out-of-order rec_b rejected
  let desync = try {
    ignore(rx.open(rec_b))
    false
  } catch {
    @record.BadRecordMac => true
    _ => false
  }
  assert_true(desync)
  assert_eq(rx.seq_num(), seq_before)
  // Tamper explicit nonce (offset 0), ciphertext (offset 8), and tag (last byte)
  for
    off in [
      0,
      7,
      8,
      15,
      rec_a.payload.length() - 16,
      rec_a.payload.length() - 1,
    ] {
    let bad = @record.RawRecord::{
      content_type: rec_a.content_type,
      version_major: rec_a.version_major,
      version_minor: rec_a.version_minor,
      payload: flip_byte(rec_a.payload, off, 0x80U),
    }
    let rejected = try {
      ignore(rx.open(bad))
      false
    } catch {
      @record.BadRecordMac => true
      _ => false
    }
    assert_true(rejected)
    assert_eq(rx.seq_num(), seq_before)
  }
  // Tamper ContentType (13B AAD mismatch)
  let bad_aad = @record.RawRecord::{
    content_type: @record.ApplicationData,
    version_major: rec_a.version_major,
    version_minor: rec_a.version_minor,
    payload: rec_a.payload,
  }
  let aad_rejected = try {
    ignore(rx.open(bad_aad))
    false
  } catch {
    @record.BadRecordMac => true
    _ => false
  }
  assert_true(aad_rejected)
  assert_eq(rx.seq_num(), seq_before)
  // Truncated GCM payload (< 24 bytes)
  let short_gcm = @record.RawRecord::{
    content_type: @record.Handshake,
    version_major: b'\x01',
    version_minor: b'\x01',
    payload: Bytes::make(23, b'\x00'),
  }
  let short_rejected = try {
    ignore(rx.open(short_gcm))
    false
  } catch {
    @record.BadRecordMac => true
    _ => false
  }
  assert_true(short_rejected)
  assert_eq(rx.seq_num(), seq_before)
  // Legitimate rec_a succeeds, replay fails, rec_b succeeds
  assert_eq(rx.open(rec_a), pt_a)
  assert_eq(rx.seq_num(), seq_before + 1UL)
  let replay = try {
    ignore(rx.open(rec_a))
    false
  } catch {
    @record.BadRecordMac => true
    _ => false
  }
  assert_true(replay)
  assert_eq(rx.seq_num(), seq_before + 1UL)
  assert_eq(rx.open(rec_b), pt_b)
  assert_eq(rx.seq_num(), seq_before + 2UL)
}

///|
test "CipherState and seal reject invalid key and IV lengths with CryptoError" {
  let bad_cbc_key = try {
    ignore(
      @record.CipherState::new_cbc(
        Bytes::make(15, b'\x00'),
        Bytes::make(32, b'\x00'),
      ),
    )
    false
  } catch {
    @record.CryptoError(_) => true
    _ => false
  }
  assert_true(bad_cbc_key)
  let bad_cbc_mac = try {
    ignore(
      @record.CipherState::new_cbc(
        Bytes::make(16, b'\x00'),
        Bytes::make(16, b'\x00'),
      ),
    )
    false
  } catch {
    @record.CryptoError(_) => true
    _ => false
  }
  assert_true(bad_cbc_mac)
  let bad_gcm_key = try {
    ignore(
      @record.CipherState::new_gcm(
        Bytes::make(32, b'\x00'),
        Bytes::make(4, b'\x00'),
      ),
    )
    false
  } catch {
    @record.CryptoError(_) => true
    _ => false
  }
  assert_true(bad_gcm_key)
  let bad_gcm_iv = try {
    ignore(
      @record.CipherState::new_gcm(
        Bytes::make(16, b'\x00'),
        Bytes::make(12, b'\x00'),
      ),
    )
    false
  } catch {
    @record.CryptoError(_) => true
    _ => false
  }
  assert_true(bad_gcm_iv)
  let layer = @record.RecordLayer::new()
  layer.set_cipher(
    @record.CipherState::new_cbc(
      Bytes::make(16, b'\x01'),
      Bytes::make(32, b'\x02'),
    ),
  )
  let bad_cbc_iv = try {
    ignore(layer.seal(@record.ApplicationData, b"hi", Bytes::make(8, b'\x00')))
    false
  } catch {
    @record.CryptoError(_) => true
    _ => false
  }
  assert_true(bad_cbc_iv)
  assert_eq(layer.seq_num(), 0UL)
  layer.set_cipher(
    @record.CipherState::new_gcm(
      Bytes::make(16, b'\x01'),
      Bytes::make(4, b'\x02'),
    ),
  )
  let bad_gcm_exp = try {
    ignore(layer.seal(@record.ApplicationData, b"hi", Bytes::make(16, b'\x00')))
    false
  } catch {
    @record.CryptoError(_) => true
    _ => false
  }
  assert_true(bad_gcm_exp)
  assert_eq(layer.seq_num(), 0UL)
}
