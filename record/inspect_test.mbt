///|
/// Unit tests for stateless wire record inspection (`inspect_record` / `inspect_record_stream`).

///|
fn build_raw_wire_record(
  ct : Byte,
  major : Byte,
  minor : Byte,
  payload : Bytes,
) -> Bytes {
  let len = payload.length()
  let out = FixedArray::make(@record.RECORD_HEADER_LEN + len, b'\x00')
  out[0] = ct
  out[1] = major
  out[2] = minor
  out[3] = ((len >> 8) & 0xFF).to_byte()
  out[4] = (len & 0xFF).to_byte()
  for i = 0; i < len; i = i + 1 {
    out[@record.RECORD_HEADER_LEN + i] = payload[i]
  }
  Bytes::from_array(out)
}

///|
fn concat_wire_records(parts : Array[Bytes]) -> Bytes {
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
test "inspect_record validates all 4 content types, version flags, and boundary lengths" {
  let cases : Array[(@record.ContentType, Byte, String, Bytes)] = [
    (@record.ChangeCipherSpec, b'\x14', "ChangeCipherSpec", b"\x01"),
    (@record.Alert, b'\x15', "Alert", b"\x02\x46"),
    (@record.Handshake, b'\x16', "Handshake", b"\x0E\x00\x00\x00"),
    (@record.ApplicationData, b'\x17', "ApplicationData", b""),
  ]
  for entry in cases {
    let (ct, ct_byte, ct_name, payload) = entry
    assert_eq(ct.name(), ct_name)
    let wire = @record.encode_record({
      content_type: ct,
      version_major: @record.TLCP_VERSION_MAJOR,
      version_minor: @record.TLCP_VERSION_MINOR,
      payload,
    })
    let view = @record.inspect_record(wire[:])
    assert_eq(view.content_type, ct_byte)
    assert_eq(view.content_type_name, ct_name)
    assert_eq(view.version_major, b'\x01')
    assert_eq(view.version_minor, b'\x01')
    assert_eq(view.is_tlcp_1_1, true)
    assert_eq(view.payload_len, payload.length())
    assert_eq(view.total_wire_len, 5 + payload.length())
    assert_eq(view.payload_offset, 5)
    assert_eq(
      wire[view.payload_offset:view.payload_offset + view.payload_len].to_owned(),
      payload,
    )
  }
  // Non-TLCP 1.1 version headers (TLS 1.2 0x0303, TLCP 1.0 0x0100) are inspected
  // with is_tlcp_1_1 == false so downstream dissectors can flag version downgrades.
  for ver in [(b'\x03', b'\x03'), (b'\x01', b'\x00'), (b'\x03', b'\x01')] {
    let (maj, min) = ver
    let wire = build_raw_wire_record(b'\x16', maj, min, b"downgrade")
    let view = @record.inspect_record(wire[:])
    assert_eq(view.content_type, b'\x16')
    assert_eq(view.content_type_name, "Handshake")
    assert_eq(view.version_major, maj)
    assert_eq(view.version_minor, min)
    assert_eq(view.is_tlcp_1_1, false)
    assert_eq(view.payload_len, 9)
    assert_eq(view.total_wire_len, 14)
    assert_eq(view.payload_offset, 5)
  }
  // Exact MAX_CIPHERTEXT_LEN (18432B) succeeds, and trailing bytes are ignored by inspect_record.
  let max_payload = Bytes::make(@record.MAX_CIPHERTEXT_LEN, b'\x5A')
  let max_wire = concat_wire_records([
    build_raw_wire_record(b'\x17', b'\x01', b'\x01', max_payload),
    b"\xFF\xFF",
  ])
  let max_view = @record.inspect_record(max_wire[:])
  assert_eq(max_view.payload_len, @record.MAX_CIPHERTEXT_LEN)
  assert_eq(max_view.total_wire_len, 5 + @record.MAX_CIPHERTEXT_LEN)
  assert_eq(max_view.is_tlcp_1_1, true)
}

///|
test "inspect_record rejects truncated headers, truncated payloads, invalid types, and overflow" {
  // Truncated headers & payloads
  let sample = build_raw_wire_record(b'\x16', b'\x01', b'\x01', b"abcdef")
  for cut = 0; cut < sample.length(); cut = cut + 1 {
    let is_incomplete = try {
      ignore(@record.inspect_record(sample[:cut]))
      false
    } catch {
      @record.Incomplete => true
      _ => false
    }
    assert_true(is_incomplete)
  }
  // Invalid content types outside 20..23
  for bad_ct in [b'\x00', b'\x13', b'\x18', b'\x80', b'\xFF'] {
    let bad_rec = build_raw_wire_record(bad_ct, b'\x01', b'\x01', b"x")
    let rejected = try {
      ignore(@record.inspect_record(bad_rec[:]))
      false
    } catch {
      @record.InvalidContentType(b) => b == bad_ct
      _ => false
    }
    assert_true(rejected)
  }
  // Record overflow (> 18432 = 0x4800) rejected immediately on 5-byte header
  for over in [(b'\x48', b'\x01', 18433), (b'\xFF', b'\xFF', 65535)] {
    let (hi, lo, expected_len) = over
    let hdr = Bytes::from_array([b'\x17', b'\x01', b'\x01', hi, lo])
    let rejected = try {
      ignore(@record.inspect_record(hdr[:]))
      false
    } catch {
      @record.RecordOverflow(n) => n == expected_len
      _ => false
    }
    assert_true(rejected)
  }
}

///|
test "inspect_record_stream walks concatenated TCP records and enforces safe max count" {
  // Empty stream returns empty array
  assert_eq(@record.inspect_record_stream(b""[:]), [])
  let p0 = b"client-hello-payload"
  let p1 = b"\x01"
  let p2 = b"\x02\x14"
  let p3 = b"encrypted-app-data"
  let r0 = build_raw_wire_record(b'\x16', b'\x01', b'\x01', p0)
  let r1 = build_raw_wire_record(b'\x14', b'\x01', b'\x01', p1)
  let r2 = build_raw_wire_record(b'\x15', b'\x03', b'\x03', p2)
  let r3 = build_raw_wire_record(b'\x17', b'\x01', b'\x01', p3)
  let stream = concat_wire_records([r0, r1, r2, r3])
  let views = @record.inspect_record_stream(stream[:])
  assert_eq(views.length(), 4)
  assert_eq(views[0].content_type_name, "Handshake")
  assert_eq(views[0].is_tlcp_1_1, true)
  assert_eq(views[0].payload_offset, 5)
  assert_eq(
    stream[views[0].payload_offset:views[0].payload_offset +
    views[0].payload_len].to_owned(),
    p0,
  )
  assert_eq(views[1].content_type_name, "ChangeCipherSpec")
  assert_eq(views[1].payload_offset, r0.length() + 5)
  assert_eq(
    stream[views[1].payload_offset:views[1].payload_offset +
    views[1].payload_len].to_owned(),
    p1,
  )
  assert_eq(views[2].content_type_name, "Alert")
  assert_eq(views[2].is_tlcp_1_1, false)
  assert_eq(
    stream[views[2].payload_offset:views[2].payload_offset +
    views[2].payload_len].to_owned(),
    p2,
  )
  assert_eq(views[3].content_type_name, "ApplicationData")
  assert_eq(views[3].is_tlcp_1_1, true)
  assert_eq(
    stream[views[3].payload_offset:views[3].payload_offset +
    views[3].payload_len].to_owned(),
    p3,
  )
  // Trailing truncated byte raises Incomplete
  let partial = concat_wire_records([r0, r1, b"\x16\x01\x01"])
  let partial_err = try {
    ignore(@record.inspect_record_stream(partial[:]))
    false
  } catch {
    @record.Incomplete => true
    _ => false
  }
  assert_true(partial_err)
  // Trailing invalid content type raises InvalidContentType
  let bad_second = concat_wire_records([
    r0,
    build_raw_wire_record(b'\x99', b'\x01', b'\x01', b""),
  ])
  let bad_ct_err = try {
    ignore(@record.inspect_record_stream(bad_second[:]))
    false
  } catch {
    @record.InvalidContentType(b'\x99') => true
    _ => false
  }
  assert_true(bad_ct_err)
  // Exact MAX_INSPECT_RECORDS empty records succeeds; MAX_INSPECT_RECORDS + 1 raises RecordOverflow
  let max_count = @record.MAX_INSPECT_RECORDS
  let max_buf = FixedArray::make(max_count * 5, b'\x00')
  for i = 0; i < max_count; i = i + 1 {
    max_buf[i * 5] = b'\x17'
    max_buf[i * 5 + 1] = b'\x01'
    max_buf[i * 5 + 2] = b'\x01'
  }
  let max_views = @record.inspect_record_stream(Bytes::from_array(max_buf)[:])
  assert_eq(max_views.length(), max_count)
  let over_buf = FixedArray::make((max_count + 1) * 5, b'\x00')
  for i = 0; i < max_count + 1; i = i + 1 {
    over_buf[i * 5] = b'\x17'
    over_buf[i * 5 + 1] = b'\x01'
    over_buf[i * 5 + 2] = b'\x01'
  }
  let flood_rejected = try {
    ignore(@record.inspect_record_stream(Bytes::from_array(over_buf)[:]))
    false
  } catch {
    @record.RecordOverflow(n) => n == max_count + 1
    _ => false
  }
  assert_true(flood_rejected)
}
