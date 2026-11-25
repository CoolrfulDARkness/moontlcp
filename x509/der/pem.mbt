///|
/// RFC 7468 PEM encoder and multi-block decoder with strict RFC 4648 Base64 validation.

///|
#derive(Debug, Eq)
pub(all) struct PemBlock {
  label : String
  data : Bytes
}

///|
let b64_alphabet : String = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

///|
fn b64_decode_char(cu : Int32) -> Int32 {
  if cu >= 0x41 && cu <= 0x5a {
    // 'A'..'Z'
    cu - 0x41
  } else if cu >= 0x61 && cu <= 0x7a {
    // 'a'..'z'
    cu - 0x61 + 26
  } else if cu >= 0x30 && cu <= 0x39 {
    // '0'..'9'
    cu - 0x30 + 52
  } else if cu == 0x2b {
    // '+'
    62
  } else if cu == 0x2f {
    // '/'
    63
  } else {
    -1
  }
}

///|
fn b64_encode(data : Bytes) -> String {
  let sb = StringBuilder()
  let len = data.length()
  let mut i = 0
  while i + 3 <= len {
    let n = (data[i].to_int() << 16) |
      (data[i + 1].to_int() << 8) |
      data[i + 2].to_int()
    sb.write_char(b64_alphabet[(n >> 18) & 0x3f].to_int().unsafe_to_char())
    sb.write_char(b64_alphabet[(n >> 12) & 0x3f].to_int().unsafe_to_char())
    sb.write_char(b64_alphabet[(n >> 6) & 0x3f].to_int().unsafe_to_char())
    sb.write_char(b64_alphabet[n & 0x3f].to_int().unsafe_to_char())
    i = i + 3
  }
  let rem = len - i
  if rem == 1 {
    let n = data[i].to_int() << 16
    sb.write_char(b64_alphabet[(n >> 18) & 0x3f].to_int().unsafe_to_char())
    sb.write_char(b64_alphabet[(n >> 12) & 0x3f].to_int().unsafe_to_char())
    sb.write_char('=')
    sb.write_char('=')
  } else if rem == 2 {
    let n = (data[i].to_int() << 16) | (data[i + 1].to_int() << 8)
    sb.write_char(b64_alphabet[(n >> 18) & 0x3f].to_int().unsafe_to_char())
    sb.write_char(b64_alphabet[(n >> 12) & 0x3f].to_int().unsafe_to_char())
    sb.write_char(b64_alphabet[(n >> 6) & 0x3f].to_int().unsafe_to_char())
    sb.write_char('=')
  }
  sb.to_string()
}

///|
fn b64_decode_strict(chars : Array[Int32]) -> Bytes raise DerError {
  let len = chars.length()
  if len == 0 {
    return b""
  }
  if len % 4 != 0 {
    raise InvalidPem("base64 length is not a multiple of 4")
  }
  let out : Array[Byte] = []
  let mut i = 0
  while i < len {
    let c0 = chars[i]
    let c1 = chars[i + 1]
    let c2 = chars[i + 2]
    let c3 = chars[i + 3]
    let v0 = b64_decode_char(c0)
    let v1 = b64_decode_char(c1)
    if v0 < 0 || v1 < 0 {
      raise InvalidPem("invalid base64 character")
    }
    let is_last = i + 4 == len
    if c2 == 0x3d {
      // '='
      if !is_last || c3 != 0x3d {
        raise InvalidPem("invalid base64 padding")
      }
      // Strict RFC 4648 §3.5: unused lower 4 bits of v1 must be zero.
      if (v1 & 0x0f) != 0 {
        raise InvalidPem("non-canonical base64 padding bits")
      }
      out.push(((v0 << 2) | (v1 >> 4)).to_byte())
    } else if c3 == 0x3d {
      if !is_last {
        raise InvalidPem("invalid base64 padding")
      }
      let v2 = b64_decode_char(c2)
      if v2 < 0 {
        raise InvalidPem("invalid base64 character")
      }
      // Strict RFC 4648 §3.5: unused lower 2 bits of v2 must be zero.
      if (v2 & 0x03) != 0 {
        raise InvalidPem("non-canonical base64 padding bits")
      }
      out.push(((v0 << 2) | (v1 >> 4)).to_byte())
      out.push((((v1 & 0x0f) << 4) | (v2 >> 2)).to_byte())
    } else {
      let v2 = b64_decode_char(c2)
      let v3 = b64_decode_char(c3)
      if v2 < 0 || v3 < 0 {
        raise InvalidPem("invalid base64 character")
      }
      out.push(((v0 << 2) | (v1 >> 4)).to_byte())
      out.push((((v1 & 0x0f) << 4) | (v2 >> 2)).to_byte())
      out.push((((v2 & 0x03) << 6) | v3).to_byte())
    }
    i = i + 4
  }
  Bytes::from_array(out)
}

///|
/// Encode binary DER `data` into RFC 7468 PEM format with 64-character line wrapping.
pub fn pem_encode(label : String, data : Bytes) -> String {
  let sb = StringBuilder()
  sb.write_string("-----BEGIN ")
  sb.write_string(label)
  sb.write_string("-----\n")
  let encoded = b64_encode(data)
  let mut offset = 0
  while offset < encoded.length() {
    let end = if offset + 64 < encoded.length() {
      offset + 64
    } else {
      encoded.length()
    }
    for i = offset; i < end; i = i + 1 {
      sb.write_char(encoded[i].to_int().unsafe_to_char())
    }
    sb.write_char('\n')
    offset = end
  }
  sb.write_string("-----END ")
  sb.write_string(label)
  sb.write_string("-----\n")
  sb.to_string()
}

///|
fn slice_line(s : String, start : Int32, end : Int32) -> String {
  s[start:end].to_owned()
}

///|
fn starts_with_str(s : String, prefix : String) -> Bool {
  if s.length() < prefix.length() {
    return false
  }
  for i = 0; i < prefix.length(); i = i + 1 {
    if s[i] != prefix[i] {
      return false
    }
  }
  true
}

///|
fn ends_with_str(s : String, suffix : String) -> Bool {
  let slen = s.length()
  let plen = suffix.length()
  if slen < plen {
    return false
  }
  let base = slen - plen
  for i = 0; i < plen; i = i + 1 {
    if s[base + i] != suffix[i] {
      return false
    }
  }
  true
}

///|
fn is_valid_pem_label(label : String) -> Bool {
  let len = label.length()
  if len == 0 {
    return false
  }
  // Reject leading or trailing whitespace.
  if label[0].to_int() == 0x20 || label[len - 1].to_int() == 0x20 {
    return false
  }
  for i = 0; i < len; i = i + 1 {
    let c = label[i].to_int()
    // Printable ASCII 0x20..0x7E excluding '-' (0x2D).
    if c < 0x20 || c > 0x7e || c == 0x2d {
      return false
    }
  }
  true
}

///|
fn split_lines_trimmed(pem : String) -> Array[String] {
  let lines : Array[String] = []
  let len = pem.length()
  let mut start = 0
  for i = 0; i <= len; i = i + 1 {
    let at_end = i == len
    let is_nl = !at_end && pem[i].to_int() == 0x0a
    if at_end || is_nl {
      let mut end = i
      // Strip trailing '\r'
      if end > start && pem[end - 1].to_int() == 0x0d {
        end = end - 1
      }
      // Strip trailing spaces/tabs
      while end > start &&
            (pem[end - 1].to_int() == 0x20 || pem[end - 1].to_int() == 0x09) {
        end = end - 1
      }
      lines.push(slice_line(pem, start, end))
      start = i + 1
    }
  }
  lines
}

///|
/// Decode all PEM blocks from `pem` (supporting multi-certificate chains and
/// explanatory text outside BEGIN/END boundaries).
pub fn pem_decode_all(pem : String) -> Array[PemBlock] raise DerError {
  let blocks : Array[PemBlock] = []
  let lines = split_lines_trimmed(pem)
  let begin_prefix = "-----BEGIN "
  let end_prefix = "-----END "
  let marker_suffix = "-----"
  let mut in_block = false
  let mut cur_label = ""
  let mut body_chars : Array[Int32] = []
  for idx = 0; idx < lines.length(); idx = idx + 1 {
    let line = lines[idx]
    if !in_block {
      if starts_with_str(line, begin_prefix) &&
        ends_with_str(line, marker_suffix) {
        if line.length() < begin_prefix.length() + marker_suffix.length() {
          raise InvalidPem("malformed BEGIN marker")
        }
        let label = slice_line(
          line,
          begin_prefix.length(),
          line.length() - marker_suffix.length(),
        )
        if !is_valid_pem_label(label) {
          raise InvalidPem("invalid PEM label")
        }
        in_block = true
        cur_label = label
        body_chars = []
      } else if starts_with_str(line, end_prefix) &&
        ends_with_str(line, marker_suffix) {
        raise InvalidPem("unexpected END marker without matching BEGIN")
      }
    } else if starts_with_str(line, end_prefix) &&
      ends_with_str(line, marker_suffix) {
      if line.length() < end_prefix.length() + marker_suffix.length() {
        raise InvalidPem("malformed END marker")
      }
      let end_label = slice_line(
        line,
        end_prefix.length(),
        line.length() - marker_suffix.length(),
      )
      if end_label != cur_label {
        raise InvalidPem("mismatched PEM END label")
      }
      let data = b64_decode_strict(body_chars)
      blocks.push({ label: cur_label, data, })
      in_block = false
      cur_label = ""
      body_chars = []
    } else if starts_with_str(line, begin_prefix) &&
      ends_with_str(line, marker_suffix) {
      raise InvalidPem("nested BEGIN marker before END")
    } else {
      for j = 0; j < line.length(); j = j + 1 {
        let cu = line[j].to_int()
        // Allow spaces/tabs inside Base64 lines; reject other invalid chars in decoder.
        if cu != 0x20 && cu != 0x09 {
          body_chars.push(cu)
        }
      }
    }
  }
  if in_block {
    raise InvalidPem("unterminated PEM block")
  }
  blocks
}
