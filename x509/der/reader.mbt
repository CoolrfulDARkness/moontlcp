///|
/// Strict ASN.1 DER Reader (ITU-T X.690).
/// Enforces canonical shortest-form lengths, forbids indefinite lengths,
/// minimal signed two's-complement INTEGER encodings, zero-padded unused bits
/// in BIT STRINGs, and canonical base-128 VLQs in OBJECT IDENTIFIERs.

///|
pub struct DerReader {
  priv data : BytesView
  priv mut pos : Int32
}

///|
/// Create a new `DerReader` over a `BytesView`.
pub fn DerReader::new(data : BytesView) -> DerReader {
  { data, pos: 0, }
}

///|
/// Return `true` if all bytes have been consumed.
pub fn DerReader::is_empty(self : DerReader) -> Bool {
  self.pos >= self.data.length()
}

///|
/// Return the number of unread bytes remaining.
pub fn DerReader::remaining(self : DerReader) -> Int32 {
  self.data.length() - self.pos
}

///|
/// Peek the next tag byte without advancing the cursor, or `None` at EOF.
pub fn DerReader::peek_tag(self : DerReader) -> Byte? {
  if self.pos >= self.data.length() {
    None
  } else {
    Some(self.data[self.pos])
  }
}

///|
/// Read a single TLV element under Strict DER rules, returning
/// `(tag, content_view, full_tlv_view)`.
pub fn DerReader::read_tlv_with_raw(
  self : DerReader,
) -> (Byte, BytesView, BytesView) raise DerError {
  let len_total = self.data.length()
  if self.pos >= len_total {
    raise UnexpectedEof
  }
  let start = self.pos
  let tag = self.data[start]
  // Reject End-of-Contents (0x00) and high-tag-number multi-octet tags (bits 0..4 all 1).
  if tag == b'\x00' || (tag.to_int() & 0x1f) == 0x1f {
    raise InvalidTag(tag)
  }
  let mut cur = start + 1
  if cur >= len_total {
    raise UnexpectedEof
  }
  let first_len = self.data[cur].to_int()
  cur = cur + 1
  let content_len = if first_len < 0x80 {
    first_len
  } else if first_len == 0x80 {
    raise IndefiniteLengthNotAllowed
  } else {
    let num_octets = first_len & 0x7f
    // 0xFF (num_octets == 127) is reserved; >4 octets cannot fit signed 32-bit Int.
    if num_octets > 4 {
      raise LengthOverflow
    }
    if num_octets > len_total - cur {
      raise UnexpectedEof
    }
    // Strict DER: leading length octet must not be 0x00.
    if self.data[cur] == b'\x00' {
      raise NonCanonicalLength
    }
    let mut acc : Int64 = 0L
    for i = 0; i < num_octets; i = i + 1 {
      acc = (acc << 8) | self.data[cur + i].to_int().to_int64()
    }
    if acc > 0x7FFF_FFFFL {
      raise LengthOverflow
    }
    let parsed = acc.to_int()
    // Strict DER: long form is only allowed when length >= 128.
    if parsed < 128 {
      raise NonCanonicalLength
    }
    cur = cur + num_octets
    parsed
  }
  if content_len > len_total - cur {
    raise UnexpectedEof
  }
  let end = cur + content_len
  let content_view = self.data[cur:end]
  let full_tlv_view = self.data[start:end]
  self.pos = end
  (tag, content_view, full_tlv_view)
}

///|
/// Read a single TLV element, returning `(tag, content_view)`.
pub fn DerReader::read_tlv(
  self : DerReader,
) -> (Byte, BytesView) raise DerError {
  let (tag, content, _) = self.read_tlv_with_raw()
  (tag, content)
}

///|
/// Read a TLV element and verify its tag equals `expected`.
/// Does not advance the cursor if the tag mismatches.
pub fn DerReader::expect_tag(
  self : DerReader,
  expected : Byte,
) -> BytesView raise DerError {
  match self.peek_tag() {
    None => raise UnexpectedEof
    Some(tag) => if tag != expected { raise InvalidTag(tag) }
  }
  let (_, content) = self.read_tlv()
  content
}

///|
/// Read an optional context-specific EXPLICIT element `[tag_num]` (tag `0xA0 | tag_num`).
/// Returns `None` without advancing if the next tag does not match or at EOF.
pub fn DerReader::read_optional_context(
  self : DerReader,
  tag_num : Int32,
) -> BytesView? raise DerError {
  if tag_num < 0 || tag_num > 30 {
    raise InvalidTag(tag_num.to_byte())
  }
  let expected = (0xa0 | tag_num).to_byte()
  match self.peek_tag() {
    Some(tag) if tag == expected => {
      let (_, content) = self.read_tlv()
      Some(content)
    }
    _ => None
  }
}

///|
/// Read a non-negative DER INTEGER as big-endian unsigned bytes (with any
/// required sign-disambiguation leading `0x00` byte stripped).
/// Rejects empty, negative, or non-minimal DER INTEGER encodings.
pub fn DerReader::read_uint_bytes(self : DerReader) -> BytesView raise DerError {
  let raw = self.expect_tag(TAG_INTEGER)
  if raw.length() == 0 {
    raise InvalidInteger
  }
  let first = raw[0].to_int()
  // Negative two's-complement integer (MSB set).
  if (first & 0x80) != 0 {
    raise InvalidInteger
  }
  if raw.length() > 1 && first == 0 {
    // Leading 0x00 is ONLY permitted when the next byte has MSB set.
    if (raw[1].to_int() & 0x80) == 0 {
      raise InvalidInteger
    }
    raw[1:]
  } else {
    raw
  }
}

///|
/// Read a non-negative DER INTEGER that fits in `UInt64`.
pub fn DerReader::read_int_u64(self : DerReader) -> UInt64 raise DerError {
  let bytes = self.read_uint_bytes()
  if bytes.length() > 8 {
    raise InvalidInteger
  }
  let mut acc : UInt64 = 0UL
  for i = 0; i < bytes.length(); i = i + 1 {
    acc = (acc << 8) | bytes[i].to_uint64()
  }
  acc
}

///|
/// Read a Strict DER BOOLEAN (`0x00` -> `false`, `0xFF` -> `true`).
/// Rejects non-1-byte lengths and non-canonical truth values (`0x01..0xFE`).
pub fn DerReader::read_boolean(self : DerReader) -> Bool raise DerError {
  let raw = self.expect_tag(TAG_BOOLEAN)
  if raw.length() != 1 {
    raise NonCanonicalLength
  }
  let b = raw[0]
  if b == b'\x00' {
    false
  } else if b == b'\xff' {
    true
  } else {
    raise NonCanonicalLength
  }
}

///|
/// Read a Strict DER NULL (must have length 0).
pub fn DerReader::read_null(self : DerReader) -> Unit raise DerError {
  let raw = self.expect_tag(TAG_NULL)
  if raw.length() != 0 {
    raise NonCanonicalLength
  }
}

///|
/// Read a primitive DER OCTET STRING.
pub fn DerReader::read_octet_string(
  self : DerReader,
) -> BytesView raise DerError {
  self.expect_tag(TAG_OCTET_STRING)
}

///|
/// Read a Strict DER BIT STRING, returning `(bit_bytes, unused_bits)`.
/// Rejects empty contents, `unused_bits > 7`, non-zero `unused_bits` on empty
/// bit strings, and any non-zero trailing unused bits in the final octet.
pub fn DerReader::read_bit_string(
  self : DerReader,
) -> (BytesView, Int32) raise DerError {
  let raw = self.expect_tag(TAG_BIT_STRING)
  if raw.length() == 0 {
    raise InvalidBitString
  }
  let unused = raw[0].to_int()
  if unused > 7 {
    raise InvalidBitString
  }
  if raw.length() == 1 {
    if unused != 0 {
      raise InvalidBitString
    }
    return (raw[1:], 0)
  }
  if unused > 0 {
    let last = raw[raw.length() - 1].to_int()
    let mask = (1 << unused) - 1
    if (last & mask) != 0 {
      raise InvalidBitString
    }
  }
  (raw[1:], unused)
}

///|
/// Parse one canonical base-128 VLQ subidentifier from `raw` starting at `offset`.
/// Returns `(value, next_offset)`.
fn read_oid_subid(
  raw : BytesView,
  offset : Int32,
) -> (UInt64, Int32) raise DerError {
  if offset >= raw.length() {
    raise InvalidOid
  }
  let first = raw[offset].to_int()
  // Strict DER (X.690 §8.19.2): leading octet of a subidentifier must not be 0x80.
  if first == 0x80 {
    raise InvalidOid
  }
  let mut acc : UInt64 = 0UL
  let mut cur = offset
  let max_before_shift : UInt64 = 0xFFFF_FFFF_FFFF_FFFFUL >> 7
  while true {
    if cur >= raw.length() {
      raise InvalidOid
    }
    let b = raw[cur].to_int()
    cur = cur + 1
    if acc > max_before_shift {
      raise InvalidOid
    }
    acc = (acc << 7) | (b & 0x7f).to_uint64()
    if (b & 0x80) == 0 {
      break
    }
  }
  (acc, cur)
}

///|
/// Read a Strict DER OBJECT IDENTIFIER as dotted decimal string (e.g. `"1.2.156.10197.1.301"`).
pub fn DerReader::read_oid(self : DerReader) -> String raise DerError {
  let raw = self.expect_tag(TAG_OID)
  if raw.length() == 0 {
    raise InvalidOid
  }
  let (first_subid, next_pos) = read_oid_subid(raw, 0)
  let (arc0, arc1) = if first_subid < 40UL {
    (0UL, first_subid)
  } else if first_subid < 80UL {
    (1UL, first_subid - 40UL)
  } else {
    (2UL, first_subid - 80UL)
  }
  let sb = StringBuilder()
  sb.write_string(arc0.to_string())
  sb.write_char('.')
  sb.write_string(arc1.to_string())
  let mut pos = next_pos
  while pos < raw.length() {
    let (subid, np) = read_oid_subid(raw, pos)
    sb.write_char('.')
    sb.write_string(subid.to_string())
    pos = np
  }
  sb.to_string()
}

///|
fn is_printable_char(b : Int32) -> Bool {
  (b >= 0x41 && b <= 0x5a) || // A-Z
  (b >= 0x61 && b <= 0x7a) || // a-z
  (b >= 0x30 && b <= 0x39) || // 0-9
  b == 0x20 || // space
  b == 0x27 || // '
  b == 0x28 || // (
  b == 0x29 || // )
  b == 0x2b || // +
  b == 0x2c || // ,
  b == 0x2d || // -
  b == 0x2e || // .
  b == 0x2f || // /
  b == 0x3a || // :
  b == 0x3d || // =
  b == 0x3f // ?
}

///|
fn decode_ascii_string(
  raw : BytesView,
  tag : Byte,
  printable_only : Bool,
) -> String raise DerError {
  let sb = StringBuilder()
  for i = 0; i < raw.length(); i = i + 1 {
    let b = raw[i].to_int()
    if printable_only {
      if !is_printable_char(b) {
        raise InvalidTag(tag)
      }
    } else if b > 0x7f {
      raise InvalidTag(tag)
    }
    sb.write_char(b.unsafe_to_char())
  }
  sb.to_string()
}

///|
fn decode_utf8_string(raw : BytesView) -> String raise DerError {
  let sb = StringBuilder()
  let len = raw.length()
  let mut i = 0
  while i < len {
    let b0 = raw[i].to_int()
    if b0 < 0x80 {
      sb.write_char(b0.unsafe_to_char())
      i = i + 1
    } else if (b0 & 0xe0) == 0xc0 {
      if i + 1 >= len {
        raise InvalidTag(TAG_UTF8_STRING)
      }
      let b1 = raw[i + 1].to_int()
      if (b1 & 0xc0) != 0x80 {
        raise InvalidTag(TAG_UTF8_STRING)
      }
      let cp = ((b0 & 0x1f) << 6) | (b1 & 0x3f)
      if cp < 0x80 {
        raise InvalidTag(TAG_UTF8_STRING)
      }
      sb.write_char(cp.unsafe_to_char())
      i = i + 2
    } else if (b0 & 0xf0) == 0xe0 {
      if i + 2 >= len {
        raise InvalidTag(TAG_UTF8_STRING)
      }
      let b1 = raw[i + 1].to_int()
      let b2 = raw[i + 2].to_int()
      if (b1 & 0xc0) != 0x80 || (b2 & 0xc0) != 0x80 {
        raise InvalidTag(TAG_UTF8_STRING)
      }
      let cp = ((b0 & 0x0f) << 12) | ((b1 & 0x3f) << 6) | (b2 & 0x3f)
      if cp < 0x800 || (cp >= 0xd800 && cp <= 0xdfff) {
        raise InvalidTag(TAG_UTF8_STRING)
      }
      sb.write_char(cp.unsafe_to_char())
      i = i + 3
    } else if (b0 & 0xf8) == 0xf0 {
      if i + 3 >= len {
        raise InvalidTag(TAG_UTF8_STRING)
      }
      let b1 = raw[i + 1].to_int()
      let b2 = raw[i + 2].to_int()
      let b3 = raw[i + 3].to_int()
      if (b1 & 0xc0) != 0x80 || (b2 & 0xc0) != 0x80 || (b3 & 0xc0) != 0x80 {
        raise InvalidTag(TAG_UTF8_STRING)
      }
      let cp = ((b0 & 0x07) << 18) |
        ((b1 & 0x3f) << 12) |
        ((b2 & 0x3f) << 6) |
        (b3 & 0x3f)
      if cp < 0x10000 || cp > 0x10ffff {
        raise InvalidTag(TAG_UTF8_STRING)
      }
      sb.write_char(cp.unsafe_to_char())
      i = i + 4
    } else {
      raise InvalidTag(TAG_UTF8_STRING)
    }
  }
  sb.to_string()
}

///|
/// Read an ASN.1 string or time value (`UTF8String`, `PrintableString`,
/// `IA5String`, `UTCTime`, or `GeneralizedTime`) into a `String`.
pub fn DerReader::read_string(self : DerReader) -> String raise DerError {
  match self.peek_tag() {
    None => raise UnexpectedEof
    Some(tag) =>
      if tag == TAG_UTF8_STRING {
        let (_, raw) = self.read_tlv()
        decode_utf8_string(raw)
      } else if tag == TAG_PRINTABLE_STRING {
        let (_, raw) = self.read_tlv()
        decode_ascii_string(raw, tag, true)
      } else if tag == TAG_IA5_STRING ||
        tag == TAG_UTC_TIME ||
        tag == TAG_GENERALIZED_TIME {
        let (_, raw) = self.read_tlv()
        decode_ascii_string(raw, tag, false)
      } else {
        raise InvalidTag(tag)
      }
  }
}

///|
/// Assert that the reader has reached the exact end of its slice.
/// Raises `TrailingData` if any unread bytes remain.
pub fn DerReader::expect_end(self : DerReader) -> Unit raise DerError {
  if !self.is_empty() {
    raise TrailingData
  }
}
