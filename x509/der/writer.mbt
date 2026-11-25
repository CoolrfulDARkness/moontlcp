///|
/// Strict ASN.1 DER Writer (ITU-T X.690).
/// Always emits canonical shortest-form lengths, minimal INTEGER representations,
/// canonical BOOLEAN (`0x00`/`0xFF`), and validated BIT STRING / OID / string encodings.

///|
pub struct DerWriter {
  priv buf : Array[Byte]
}

///|
/// Create an empty `DerWriter`.
pub fn DerWriter::new() -> DerWriter {
  { buf: [], }
}

///|
/// Finalize and return the encoded DER `Bytes`.
pub fn DerWriter::to_bytes(self : DerWriter) -> Bytes {
  Bytes::from_array(self.buf)
}

///|
fn DerWriter::write_length(self : DerWriter, len : Int32) -> Unit {
  if len < 0x80 {
    self.buf.push(len.to_byte())
  } else if len <= 0xff {
    self.buf.push(b'\x81')
    self.buf.push(len.to_byte())
  } else if len <= 0xffff {
    self.buf.push(b'\x82')
    self.buf.push((len >> 8).to_byte())
    self.buf.push((len & 0xff).to_byte())
  } else if len <= 0xffffff {
    self.buf.push(b'\x83')
    self.buf.push((len >> 16).to_byte())
    self.buf.push(((len >> 8) & 0xff).to_byte())
    self.buf.push((len & 0xff).to_byte())
  } else {
    self.buf.push(b'\x84')
    self.buf.push(((len >> 24) & 0xff).to_byte())
    self.buf.push(((len >> 16) & 0xff).to_byte())
    self.buf.push(((len >> 8) & 0xff).to_byte())
    self.buf.push((len & 0xff).to_byte())
  }
}

///|
/// Write a raw TLV with the specified tag and content bytes.
pub fn DerWriter::write_tlv(
  self : DerWriter,
  tag : Byte,
  content : BytesView,
) -> Unit {
  self.buf.push(tag)
  self.write_length(content.length())
  for i = 0; i < content.length(); i = i + 1 {
    self.buf.push(content[i])
  }
}

///|
/// Write a constructed SEQUENCE (`0x30`) populated by callback `f`.
pub fn DerWriter::write_sequence(
  self : DerWriter,
  f : (DerWriter) -> Unit raise?,
) -> Unit raise? {
  let inner = DerWriter::new()
  f(inner)
  self.write_tlv(TAG_SEQUENCE, inner.to_bytes()[:])
}

///|
/// Write a constructed SET (`0x31`) populated by callback `f`.
pub fn DerWriter::write_set(
  self : DerWriter,
  f : (DerWriter) -> Unit raise?,
) -> Unit raise? {
  let inner = DerWriter::new()
  f(inner)
  self.write_tlv(TAG_SET, inner.to_bytes()[:])
}

///|
/// Write a context-specific EXPLICIT wrapper `[tag_num]` (`0xA0 | tag_num`)
/// populated by callback `f`.
pub fn DerWriter::write_context_explicit(
  self : DerWriter,
  tag_num : Int32,
  f : (DerWriter) -> Unit raise DerError,
) -> Unit raise DerError {
  if tag_num < 0 || tag_num > 30 {
    raise InvalidTag(tag_num.to_byte())
  }
  let inner = DerWriter::new()
  f(inner)
  self.write_tlv((0xa0 | tag_num).to_byte(), inner.to_bytes()[:])
}

///|
/// Write an unsigned big-endian integer byte slice as a canonical non-negative
/// DER INTEGER (stripping redundant leading zeros and prepending `0x00` iff
/// the most significant byte has bit 7 set).
pub fn DerWriter::write_uint_bytes(self : DerWriter, data : BytesView) -> Unit {
  let mut start = 0
  while start < data.length() && data[start] == b'\x00' {
    start = start + 1
  }
  if start == data.length() {
    // Value is zero.
    self.buf.push(TAG_INTEGER)
    self.buf.push(b'\x01')
    self.buf.push(b'\x00')
    return
  }
  let trimmed = data[start:]
  let need_pad = (trimmed[0].to_int() & 0x80) != 0
  let total_len = trimmed.length() + (if need_pad { 1 } else { 0 })
  self.buf.push(TAG_INTEGER)
  self.write_length(total_len)
  if need_pad {
    self.buf.push(b'\x00')
  }
  for i = 0; i < trimmed.length(); i = i + 1 {
    self.buf.push(trimmed[i])
  }
}

///|
/// Write a `UInt64` as a canonical non-negative DER INTEGER.
pub fn DerWriter::write_int_u64(self : DerWriter, value : UInt64) -> Unit {
  let tmp : FixedArray[Byte] = FixedArray::make(8, b'\x00')
  for i = 0; i < 8; i = i + 1 {
    tmp[7 - i] = ((value >> (i * 8)) & 0xffUL).to_byte()
  }
  let raw = Bytes::from_array(tmp)
  self.write_uint_bytes(raw[:])
}

///|
/// Write a Strict DER BOOLEAN (`true` -> `0xFF`, `false` -> `0x00`).
pub fn DerWriter::write_boolean(self : DerWriter, value : Bool) -> Unit {
  self.buf.push(TAG_BOOLEAN)
  self.buf.push(b'\x01')
  self.buf.push(if value { b'\xff' } else { b'\x00' })
}

///|
/// Write a Strict DER NULL (`05 00`).
pub fn DerWriter::write_null(self : DerWriter) -> Unit {
  self.buf.push(TAG_NULL)
  self.buf.push(b'\x00')
}

///|
/// Write a DER OCTET STRING.
pub fn DerWriter::write_octet_string(
  self : DerWriter,
  data : BytesView,
) -> Unit {
  self.write_tlv(TAG_OCTET_STRING, data)
}

///|
/// Write a Strict DER BIT STRING.
/// Validates `0 <= unused_bits <= 7`, empty bit string requires `unused_bits == 0`,
/// and trailing unused bits of the final octet must be zero.
pub fn DerWriter::write_bit_string(
  self : DerWriter,
  data : BytesView,
  unused_bits~ : Int32 = 0,
) -> Unit raise DerError {
  if unused_bits < 0 || unused_bits > 7 {
    raise InvalidBitString
  }
  if data.length() == 0 {
    if unused_bits != 0 {
      raise InvalidBitString
    }
  } else if unused_bits > 0 {
    let last = data[data.length() - 1].to_int()
    let mask = (1 << unused_bits) - 1
    if (last & mask) != 0 {
      raise InvalidBitString
    }
  }
  self.buf.push(TAG_BIT_STRING)
  self.write_length(1 + data.length())
  self.buf.push(unused_bits.to_byte())
  for i = 0; i < data.length(); i = i + 1 {
    self.buf.push(data[i])
  }
}

///|
fn encode_oid_subid(out : Array[Byte], value : UInt64) -> Unit {
  if value < 128UL {
    out.push(value.to_byte())
    return
  }
  let tmp : Array[Byte] = []
  let mut v = value
  tmp.push((v & 0x7fUL).to_byte())
  v = v >> 7
  while v > 0UL {
    tmp.push(((v & 0x7fUL) | 0x80UL).to_byte())
    v = v >> 7
  }
  for i = tmp.length() - 1; i >= 0; i = i - 1 {
    out.push(tmp[i])
  }
}

///|
fn parse_oid_arcs(oid : String) -> Array[UInt64] raise DerError {
  if oid.length() == 0 {
    raise InvalidOid
  }
  let arcs : Array[UInt64] = []
  let mut acc : UInt64 = 0UL
  let mut digits = 0
  let mut first_digit = -1
  let max_div10 : UInt64 = 0xFFFF_FFFF_FFFF_FFFFUL / 10UL
  let max_mod10 : UInt64 = 0xFFFF_FFFF_FFFF_FFFFUL % 10UL
  for i = 0; i < oid.length(); i = i + 1 {
    let cu = oid[i].to_int()
    if cu == 0x2e {
      // '.'
      if digits == 0 {
        raise InvalidOid
      }
      arcs.push(acc)
      acc = 0UL
      digits = 0
      first_digit = -1
    } else if cu >= 0x30 && cu <= 0x39 {
      let d = cu - 0x30
      if digits == 0 {
        first_digit = d
      } else if first_digit == 0 {
        // Reject leading zeros like "1.02.3".
        raise InvalidOid
      }
      let du = d.to_uint64()
      if acc > max_div10 || (acc == max_div10 && du > max_mod10) {
        raise InvalidOid
      }
      acc = acc * 10UL + du
      digits = digits + 1
    } else {
      raise InvalidOid
    }
  }
  if digits == 0 {
    raise InvalidOid
  }
  arcs.push(acc)
  arcs
}

///|
/// Write a dotted decimal OBJECT IDENTIFIER (e.g. `"1.2.156.10197.1.301"`).
pub fn DerWriter::write_oid(
  self : DerWriter,
  oid : String,
) -> Unit raise DerError {
  let arcs = parse_oid_arcs(oid)
  if arcs.length() < 2 {
    raise InvalidOid
  }
  let arc0 = arcs[0]
  let arc1 = arcs[1]
  if arc0 > 2UL {
    raise InvalidOid
  }
  if arc0 < 2UL && arc1 >= 40UL {
    raise InvalidOid
  }
  let first_base = arc0 * 40UL
  if arc1 > 0xFFFF_FFFF_FFFF_FFFFUL - first_base {
    raise InvalidOid
  }
  let encoded : Array[Byte] = []
  encode_oid_subid(encoded, first_base + arc1)
  for i = 2; i < arcs.length(); i = i + 1 {
    encode_oid_subid(encoded, arcs[i])
  }
  self.write_tlv(TAG_OID, Bytes::from_array(encoded)[:])
}

///|
/// Write a DER UTF8String (`0x0C`), encoding the MoonBit `String` as UTF-8.
pub fn DerWriter::write_utf8_string(self : DerWriter, s : String) -> Unit {
  let out : Array[Byte] = []
  for ch in s {
    let cp = ch.to_int()
    if cp < 0x80 {
      out.push(cp.to_byte())
    } else if cp < 0x800 {
      out.push((0xc0 | (cp >> 6)).to_byte())
      out.push((0x80 | (cp & 0x3f)).to_byte())
    } else if cp < 0x10000 {
      out.push((0xe0 | (cp >> 12)).to_byte())
      out.push((0x80 | ((cp >> 6) & 0x3f)).to_byte())
      out.push((0x80 | (cp & 0x3f)).to_byte())
    } else {
      out.push((0xf0 | (cp >> 18)).to_byte())
      out.push((0x80 | ((cp >> 12) & 0x3f)).to_byte())
      out.push((0x80 | ((cp >> 6) & 0x3f)).to_byte())
      out.push((0x80 | (cp & 0x3f)).to_byte())
    }
  }
  self.write_tlv(TAG_UTF8_STRING, Bytes::from_array(out)[:])
}

///|
/// Write a DER PrintableString (`0x13`), validating every character against
/// the ASN.1 PrintableString character set.
pub fn DerWriter::write_printable_string(
  self : DerWriter,
  s : String,
) -> Unit raise DerError {
  let out : Array[Byte] = []
  for ch in s {
    let cp = ch.to_int()
    if !is_printable_char(cp) {
      raise InvalidTag(TAG_PRINTABLE_STRING)
    }
    out.push(cp.to_byte())
  }
  self.write_tlv(TAG_PRINTABLE_STRING, Bytes::from_array(out)[:])
}

///|
fn parse_two_digits(s : String, offset : Int32) -> Int32? {
  let d0 = s[offset].to_int() - 0x30
  let d1 = s[offset + 1].to_int() - 0x30
  if d0 < 0 || d0 > 9 || d1 < 0 || d1 > 9 {
    None
  } else {
    Some(d0 * 10 + d1)
  }
}

///|
/// Write a Strict DER UTCTime (`0x17`), requiring exact `YYMMDDHHMMSSZ` format.
pub fn DerWriter::write_utc_time(
  self : DerWriter,
  s : String,
) -> Unit raise DerError {
  if s.length() != 13 || s[12].to_int() != 0x5a {
    // Must be 13 chars ending with 'Z'.
    raise InvalidTag(TAG_UTC_TIME)
  }
  match
    (
      parse_two_digits(s, 0),
      parse_two_digits(s, 2),
      parse_two_digits(s, 4),
      parse_two_digits(s, 6),
      parse_two_digits(s, 8),
      parse_two_digits(s, 10),
    ) {
    (Some(_), Some(mon), Some(day), Some(hr), Some(min), Some(sec)) =>
      if mon < 1 ||
        mon > 12 ||
        day < 1 ||
        day > 31 ||
        hr > 23 ||
        min > 59 ||
        sec > 59 {
        raise InvalidTag(TAG_UTC_TIME)
      }
    _ => raise InvalidTag(TAG_UTC_TIME)
  }
  let out : Array[Byte] = []
  for i = 0; i < 13; i = i + 1 {
    out.push(s[i].to_int().to_byte())
  }
  self.write_tlv(TAG_UTC_TIME, Bytes::from_array(out)[:])
}
