///|
/// Stateless, read-only GM/T 0024-2023 (TLCP 1.1) wire record dissector APIs.
///
/// Designed for zero-coupling packet analyzers (e.g. `moonshark`) and passive
/// traffic inspection without holding cipher or sequence state.

///|
/// Maximum number of concatenated records walked by `inspect_record_stream` in
/// a single call, bounding worst-case work against tiny-record stream floods.
pub const MAX_INSPECT_RECORDS : Int32 = 1024

///|
/// Returns the human-readable GM/T 0024-2023 name for a TLCP record `ContentType`.
pub fn ContentType::name(self : ContentType) -> String {
  match self {
    ChangeCipherSpec => "ChangeCipherSpec"
    Alert => "Alert"
    Handshake => "Handshake"
    ApplicationData => "ApplicationData"
  }
}

///|
/// Read-only metadata view of a single TLCP/TLS wire record header and payload bounds.
#derive(Debug, Eq)
pub(all) struct RecordView {
  content_type : Byte
  content_type_name : String
  version_major : Byte
  version_minor : Byte
  is_tlcp_1_1 : Bool
  payload_len : Int32
  total_wire_len : Int32
  payload_offset : Int32
}

///|
fn inspect_record_at(
  raw : BytesView,
  base_offset : Int32,
) -> RecordView raise RecordError {
  let remaining = raw.length() - base_offset
  if remaining < RECORD_HEADER_LEN {
    raise Incomplete
  }
  let content_type = raw[base_offset]
  let ct = ContentType::from_byte(content_type)
  let version_major = raw[base_offset + 1]
  let version_minor = raw[base_offset + 2]
  let is_tlcp_1_1 = version_major == TLCP_VERSION_MAJOR &&
    version_minor == TLCP_VERSION_MINOR
  let payload_len = (raw[base_offset + 3].to_int() << 8) |
    raw[base_offset + 4].to_int()
  if payload_len > MAX_CIPHERTEXT_LEN {
    raise RecordOverflow(payload_len)
  }
  let total_wire_len = RECORD_HEADER_LEN + payload_len
  if remaining < total_wire_len {
    raise Incomplete
  }
  {
    content_type,
    content_type_name: ct.name(),
    version_major,
    version_minor,
    is_tlcp_1_1,
    payload_len,
    total_wire_len,
    payload_offset: base_offset + RECORD_HEADER_LEN,
  }
}

///|
/// Statelessly inspects a single TLCP/TLS wire record at the start of `raw`.
///
/// Validates the 5-byte record header, checks that `content_type` is in `20..23`,
/// sets `is_tlcp_1_1` for protocol version `0x0101` (without rejecting other
/// versions so dissectors can flag downgrade packets), enforces
/// `payload_len <= MAX_CIPHERTEXT_LEN`, and checks `raw.length() >= 5 + payload_len`.
pub fn inspect_record(raw : BytesView) -> RecordView raise RecordError {
  inspect_record_at(raw, 0)
}

///|
/// Statelessly walks concatenated TLCP/TLS wire records from a TCP stream slice.
///
/// Each returned `RecordView` records its absolute `payload_offset` within `raw`
/// so callers can slice payloads via `raw[v.payload_offset : v.payload_offset + v.payload_len]`.
/// Returns `[]` on an empty slice, raises `Incomplete` on a truncated trailing
/// record, and raises `RecordOverflow` if more than `MAX_INSPECT_RECORDS` records
/// appear in one buffer.
pub fn inspect_record_stream(
  raw : BytesView,
) -> Array[RecordView] raise RecordError {
  let views : Array[RecordView] = []
  let mut off = 0
  while off < raw.length() {
    if views.length() >= MAX_INSPECT_RECORDS {
      raise RecordOverflow(views.length() + 1)
    }
    let view = inspect_record_at(raw, off)
    views.push(view)
    off = off + view.total_wire_len
  }
  views
}
