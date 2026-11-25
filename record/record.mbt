///|
/// GM/T 0024-2023 (GB/T 38636-2020) §6.2 TLCP 1.1 (0x0101) Record Layer.
///
/// Provides record framing, 16KB plaintext fragmentation, sequence number
/// overflow protection, constant-time Lucky13-resistant SM4-CBC-HMAC-SM3
/// record protection, and SM4-GCM AEAD record protection.

///|
pub const TLCP_VERSION_MAJOR : Byte = b'\x01'

///|
pub const TLCP_VERSION_MINOR : Byte = b'\x01'

///|
pub const TLCP_VERSION_U16 : UInt32 = 0x0101U

///|
pub const RECORD_HEADER_LEN : Int32 = 5

///|
pub const MAX_PLAINTEXT_LEN : Int32 = 16384

///|
pub const MAX_CIPHERTEXT_LEN : Int32 = 18432

///|
const CBC_IV_LEN : Int32 = 16

///|
const GCM_IMPLICIT_IV_LEN : Int32 = 4

///|
const GCM_EXPLICIT_NONCE_LEN : Int32 = 8

///|
const GCM_NONCE_LEN : Int32 = 12

///|
const GCM_TAG_LEN : Int32 = 16

///|
const MAX_SEQ_NUM : UInt64 = 0xFFFFFFFFFFFFFFFFUL

///|
#derive(Debug, Eq)
pub(all) enum ContentType {
  ChangeCipherSpec
  Alert
  Handshake
  ApplicationData
}

///|
/// Encodes a TLCP `ContentType` to its wire byte value (20..23).
pub fn ContentType::to_byte(self : ContentType) -> Byte {
  match self {
    ChangeCipherSpec => b'\x14'
    Alert => b'\x15'
    Handshake => b'\x16'
    ApplicationData => b'\x17'
  }
}

///|
/// Decodes a wire byte into a TLCP `ContentType`, raising `InvalidContentType`
/// for unknown record types.
pub fn ContentType::from_byte(b : Byte) -> ContentType raise RecordError {
  match b {
    b'\x14' => ChangeCipherSpec
    b'\x15' => Alert
    b'\x16' => Handshake
    b'\x17' => ApplicationData
    _ => raise InvalidContentType(b)
  }
}

///|
#derive(Debug, Eq)
pub suberror RecordError {
  Incomplete
  InvalidContentType(Byte)
  UnsupportedVersion(Byte, Byte)
  RecordOverflow(Int32)
  BadRecordMac
  SequenceOverflow
  CryptoError(String)
}

///|
#derive(Debug, Eq)
pub(all) struct RawRecord {
  content_type : ContentType
  version_major : Byte
  version_minor : Byte
  payload : Bytes
}

///|
/// Serializes a `RawRecord` into wire format:
/// `[content_type(1B), version_major(1B), version_minor(1B), length(2B BE), payload]`.
pub fn encode_record(rec : RawRecord) -> Bytes raise RecordError {
  let len = rec.payload.length()
  if len > MAX_CIPHERTEXT_LEN {
    raise RecordOverflow(len)
  }
  let out = FixedArray::make(RECORD_HEADER_LEN + len, b'\x00')
  out[0] = rec.content_type.to_byte()
  out[1] = rec.version_major
  out[2] = rec.version_minor
  out[3] = ((len >> 8) & 0xFF).to_byte()
  out[4] = (len & 0xFF).to_byte()
  for i = 0; i < len; i = i + 1 {
    out[RECORD_HEADER_LEN + i] = rec.payload[i]
  }
  Bytes::from_array(out)
}

///|
/// Parses a single TLCP 1.1 (`0x0101`) record from `buf`, returning `(record, bytes_consumed)`.
/// Rejects truncated buffers with `Incomplete`, non-`0x0101` versions with
/// `UnsupportedVersion`, invalid types with `InvalidContentType`, and payloads
/// exceeding `MAX_CIPHERTEXT_LEN` with `RecordOverflow`.
pub fn decode_record(buf : BytesView) -> (RawRecord, Int32) raise RecordError {
  if buf.length() < RECORD_HEADER_LEN {
    raise Incomplete
  }
  let content_type = ContentType::from_byte(buf[0])
  let version_major = buf[1]
  let version_minor = buf[2]
  if version_major != TLCP_VERSION_MAJOR || version_minor != TLCP_VERSION_MINOR {
    raise UnsupportedVersion(version_major, version_minor)
  }
  let length = (buf[3].to_int() << 8) | buf[4].to_int()
  if length > MAX_CIPHERTEXT_LEN {
    raise RecordOverflow(length)
  }
  let total = RECORD_HEADER_LEN + length
  if buf.length() < total {
    raise Incomplete
  }
  let payload = FixedArray::make(length, b'\x00')
  for i = 0; i < length; i = i + 1 {
    payload[i] = buf[RECORD_HEADER_LEN + i]
  }
  (
    RawRecord::{
      content_type,
      version_major,
      version_minor,
      payload: Bytes::from_array(payload),
    },
    total,
  )
}

///|
/// Splits plaintext `data` into TLCP 1.1 `RawRecord` fragments of at most
/// `MAX_PLAINTEXT_LEN` (16384) bytes each.
pub fn fragment_plaintext(
  content_type : ContentType,
  data : Bytes,
) -> Array[RawRecord] {
  let out : Array[RawRecord] = []
  if data.length() == 0 {
    out.push(RawRecord::{
      content_type,
      version_major: TLCP_VERSION_MAJOR,
      version_minor: TLCP_VERSION_MINOR,
      payload: b"",
    })
    return out
  }
  let mut off = 0
  while off < data.length() {
    let take = if data.length() - off < MAX_PLAINTEXT_LEN {
      data.length() - off
    } else {
      MAX_PLAINTEXT_LEN
    }
    let chunk = FixedArray::make(take, b'\x00')
    for i = 0; i < take; i = i + 1 {
      chunk[i] = data[off + i]
    }
    out.push(RawRecord::{
      content_type,
      version_major: TLCP_VERSION_MAJOR,
      version_minor: TLCP_VERSION_MINOR,
      payload: Bytes::from_array(chunk),
    })
    off = off + take
  }
  out
}

///|
/// Active symmetric protection state for one direction of a TLCP record layer.
pub enum CipherState {
  Null
  Sm4CbcHmacSm3(@sm4.Sm4Key, Bytes)
  Sm4Gcm(@sm4.Sm4Key, Bytes)
}

///|
/// Creates an unprotected (null) cipher state used prior to `ChangeCipherSpec`.
pub fn CipherState::null() -> CipherState {
  Null
}

///|
fn sm4_err_msg(err : @sm4.Sm4Error) -> String {
  match err {
    @sm4.InvalidKeyLength(n) => "invalid SM4 key length: " + n.to_string()
    @sm4.InvalidIvLength(n) => "invalid SM4 IV length: " + n.to_string()
    @sm4.InvalidBlockLength(n) => "invalid SM4 block length: " + n.to_string()
    @sm4.InvalidPadding => "invalid SM4 padding"
    @sm4.AuthFailed => "SM4 authentication failed"
  }
}

///|
/// Creates an `SM4-CBC-HMAC-SM3` cipher state (16-byte SM4 key, 32-byte HMAC-SM3 key).
pub fn CipherState::new_cbc(
  enc_key : Bytes,
  mac_key : Bytes,
) -> CipherState raise RecordError {
  if mac_key.length() != @sm3.SM3_DIGEST_SIZE {
    raise CryptoError(
      "invalid HMAC-SM3 MAC key length: expected 32 bytes, got " +
      mac_key.length().to_string(),
    )
  }
  let sm4 = @sm4.Sm4Key::new(enc_key) catch {
    err => raise CryptoError("SM4 key init failed: " + sm4_err_msg(err))
  }
  Sm4CbcHmacSm3(sm4, mac_key)
}

///|
/// Creates an `SM4-GCM` AEAD cipher state (16-byte SM4 key, 4-byte implicit IV salt).
pub fn CipherState::new_gcm(
  enc_key : Bytes,
  implicit_iv : Bytes,
) -> CipherState raise RecordError {
  if implicit_iv.length() != GCM_IMPLICIT_IV_LEN {
    raise CryptoError(
      "invalid SM4-GCM implicit IV length: expected 4 bytes, got " +
      implicit_iv.length().to_string(),
    )
  }
  let sm4 = @sm4.Sm4Key::new(enc_key) catch {
    err => raise CryptoError("SM4 key init failed: " + sm4_err_msg(err))
  }
  Sm4Gcm(sm4, implicit_iv)
}

///|
/// Builds the 13-byte TLCP 1.1 MAC / AEAD additional authenticated data header:
/// `seq_num (8B BE) || content_type (1B) || 0x01 || 0x01 || plaintext_len (2B BE)`.
fn build_aad(
  seq : UInt64,
  content_type : ContentType,
  plaintext_len : Int32,
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
  aad[8] = content_type.to_byte()
  aad[9] = TLCP_VERSION_MAJOR
  aad[10] = TLCP_VERSION_MINOR
  aad[11] = ((plaintext_len >> 8) & 0xFF).to_byte()
  aad[12] = (plaintext_len & 0xFF).to_byte()
  Bytes::from_array(aad)
}

///|
/// Stateful one-directional TLCP 1.1 record layer tracking cipher state and
/// 64-bit record sequence number.
pub struct RecordLayer {
  mut cipher : CipherState
  mut seq : UInt64
}

///|
/// Creates a new `RecordLayer` initialized with `CipherState::null()` and `seq = 0`.
pub fn RecordLayer::new() -> RecordLayer {
  { cipher: Null, seq: 0UL, }
}

///|
/// Switches the active cipher state and resets the sequence number to zero
/// per GM/T 0024-2023 §6.2.1.
pub fn RecordLayer::set_cipher(
  self : RecordLayer,
  cipher : CipherState,
) -> Unit {
  self.cipher = cipher
  self.seq = 0UL
}

///|
/// Returns the current 64-bit record sequence number.
pub fn RecordLayer::seq_num(self : RecordLayer) -> UInt64 {
  self.seq
}

///|
/// Protects a plaintext fragment and encodes a complete TLCP 1.1 wire record.
///
/// - For `Null`: `explicit_iv` is unused.
/// - For `SM4-CBC-HMAC-SM3`: `explicit_iv` must be 16 bytes.
/// - For `SM4-GCM`: `explicit_iv` must be 8 bytes (appended to 4-byte implicit IV).
///
/// Increments `seq` only after encryption and encoding succeed.
pub fn RecordLayer::seal(
  self : RecordLayer,
  content_type : ContentType,
  plaintext : Bytes,
  explicit_iv : Bytes,
) -> Bytes raise RecordError {
  if plaintext.length() > MAX_PLAINTEXT_LEN {
    raise RecordOverflow(plaintext.length())
  }
  if self.seq == MAX_SEQ_NUM {
    raise SequenceOverflow
  }
  let payload = match self.cipher {
    Null => plaintext
    Sm4CbcHmacSm3(sm4, mac_key) => {
      if explicit_iv.length() != CBC_IV_LEN {
        raise CryptoError(
          "invalid SM4-CBC explicit IV length: expected 16 bytes, got " +
          explicit_iv.length().to_string(),
        )
      }
      let aad = build_aad(self.seq, content_type, plaintext.length())
      let mac = @sm3.hmac_sm3_parts(mac_key, [aad[:], plaintext[:]])
      // TLS/TLCP block padding: pad_len in 0..=15, appending (pad_len + 1) bytes of value pad_len
      let base_len = plaintext.length() + @sm3.SM3_DIGEST_SIZE
      let rem = (base_len + 1) % @sm4.SM4_BLOCK_SIZE
      let pad_len = (@sm4.SM4_BLOCK_SIZE - rem) % @sm4.SM4_BLOCK_SIZE
      let total_pad = pad_len + 1
      let padded = FixedArray::make(base_len + total_pad, pad_len.to_byte())
      for i = 0; i < plaintext.length(); i = i + 1 {
        padded[i] = plaintext[i]
      }
      for i = 0; i < @sm3.SM3_DIGEST_SIZE; i = i + 1 {
        padded[plaintext.length() + i] = mac[i]
      }
      let ciphertext = sm4.cbc_encrypt_raw(
        explicit_iv,
        Bytes::from_array(padded),
      ) catch {
        err => raise CryptoError("SM4-CBC encrypt failed: " + sm4_err_msg(err))
      }
      let out = FixedArray::make(CBC_IV_LEN + ciphertext.length(), b'\x00')
      for i = 0; i < CBC_IV_LEN; i = i + 1 {
        out[i] = explicit_iv[i]
      }
      for i = 0; i < ciphertext.length(); i = i + 1 {
        out[CBC_IV_LEN + i] = ciphertext[i]
      }
      Bytes::from_array(out)
    }
    Sm4Gcm(sm4, implicit_iv) => {
      if explicit_iv.length() != GCM_EXPLICIT_NONCE_LEN {
        raise CryptoError(
          "invalid SM4-GCM explicit nonce length: expected 8 bytes, got " +
          explicit_iv.length().to_string(),
        )
      }
      let nonce = FixedArray::make(GCM_NONCE_LEN, b'\x00')
      for i = 0; i < GCM_IMPLICIT_IV_LEN; i = i + 1 {
        nonce[i] = implicit_iv[i]
      }
      for i = 0; i < GCM_EXPLICIT_NONCE_LEN; i = i + 1 {
        nonce[GCM_IMPLICIT_IV_LEN + i] = explicit_iv[i]
      }
      let aad = build_aad(self.seq, content_type, plaintext.length())
      let (ciphertext, tag) = sm4.gcm_encrypt(
        Bytes::from_array(nonce),
        aad,
        plaintext,
      ) catch {
        err => raise CryptoError("SM4-GCM encrypt failed: " + sm4_err_msg(err))
      }
      let out = FixedArray::make(
        GCM_EXPLICIT_NONCE_LEN + ciphertext.length() + GCM_TAG_LEN,
        b'\x00',
      )
      for i = 0; i < GCM_EXPLICIT_NONCE_LEN; i = i + 1 {
        out[i] = explicit_iv[i]
      }
      for i = 0; i < ciphertext.length(); i = i + 1 {
        out[GCM_EXPLICIT_NONCE_LEN + i] = ciphertext[i]
      }
      for i = 0; i < GCM_TAG_LEN; i = i + 1 {
        out[GCM_EXPLICIT_NONCE_LEN + ciphertext.length() + i] = tag[i]
      }
      Bytes::from_array(out)
    }
  }
  let wire = encode_record(RawRecord::{
    content_type,
    version_major: TLCP_VERSION_MAJOR,
    version_minor: TLCP_VERSION_MINOR,
    payload,
  })
  self.seq = self.seq + 1UL
  wire
}

///|
/// Decrypts and authenticates a received `RawRecord`, returning the plaintext.
///
/// - Enforces TLCP 1.1 (`0x0101`) version and length limits.
/// - For `SM4-CBC-HMAC-SM3`: performs constant-time TLS padding verification,
///   constant-time MAC extraction, and Lucky13 block-count equalization;
///   all padding and MAC failures uniformly raise `BadRecordMac`.
/// - For `SM4-GCM`: verifies 12-byte nonce, 13-byte AAD, and 16-byte tag;
///   any authentication failure raises `BadRecordMac`.
/// - Increments `seq` strictly after verification succeeds.
pub fn RecordLayer::open(
  self : RecordLayer,
  rec : RawRecord,
) -> Bytes raise RecordError {
  if rec.version_major != TLCP_VERSION_MAJOR ||
    rec.version_minor != TLCP_VERSION_MINOR {
    raise UnsupportedVersion(rec.version_major, rec.version_minor)
  }
  if rec.payload.length() > MAX_CIPHERTEXT_LEN {
    raise RecordOverflow(rec.payload.length())
  }
  if self.seq == MAX_SEQ_NUM {
    raise SequenceOverflow
  }
  let plaintext = match self.cipher {
    Null => {
      if rec.payload.length() > MAX_PLAINTEXT_LEN {
        raise RecordOverflow(rec.payload.length())
      }
      rec.payload
    }
    Sm4CbcHmacSm3(sm4, mac_key) => {
      // Minimum CBC payload: 16B explicit IV + 48B ciphertext (0B pt + 32B MAC + >=1B pad, aligned to 16B)
      let payload_len = rec.payload.length()
      let ct_len = payload_len - CBC_IV_LEN
      if payload_len < CBC_IV_LEN + 48 || ct_len % @sm4.SM4_BLOCK_SIZE != 0 {
        raise BadRecordMac
      }
      let iv = FixedArray::make(CBC_IV_LEN, b'\x00')
      for i = 0; i < CBC_IV_LEN; i = i + 1 {
        iv[i] = rec.payload[i]
      }
      let ct = FixedArray::make(ct_len, b'\x00')
      for i = 0; i < ct_len; i = i + 1 {
        ct[i] = rec.payload[CBC_IV_LEN + i]
      }
      let dec = sm4.cbc_decrypt_raw(
        Bytes::from_array(iv),
        Bytes::from_array(ct),
      ) catch {
        _ => raise BadRecordMac
      }
      let n = dec.length()
      // Constant-time TLS/TLCP padding validation:
      // last byte is pad_len (0..=255), total padding bytes = pad_len + 1 (1..=256).
      let pad_len = dec[n - 1].to_uint()
      let total_pad = pad_len + 1U
      let max_pad_plus_one = (n - @sm3.SM3_DIGEST_SIZE + 1).reinterpret_as_uint()
      let mut pad_good = @ct.ct_lt_u32(total_pad, max_pad_plus_one)
      let to_check = if n < 256 { n } else { 256 }
      for i = 0; i < to_check; i = i + 1 {
        let in_pad = @ct.ct_lt_u32(i.reinterpret_as_uint(), total_pad)
        let b = dec[n - 1 - i].to_uint()
        let byte_ok = @ct.ct_eq_u32(b, pad_len)
        pad_good = pad_good & @ct.ct_select_u32(in_pad, byte_ok, 1U)
      }
      // Compute effective plaintext length in constant time; fall back to (n - 33) on bad padding
      // so MAC extraction and HMAC computation always run in constant time without early exit.
      let raw_pt_len = n.reinterpret_as_uint() -
        @sm3.SM3_DIGEST_SIZE.reinterpret_as_uint() -
        total_pad
      let fallback_pt_len = (n - @sm3.SM3_DIGEST_SIZE - 1).reinterpret_as_uint()
      let pt_len_u = @ct.ct_select_u32(pad_good, raw_pt_len, fallback_pt_len)
      let pt_len = pt_len_u.reinterpret_as_int()
      // Constant-time MAC extraction across the fixed public window [scan_start, n - 33]
      let received_mac = FixedArray::make(@sm3.SM3_DIGEST_SIZE, b'\x00')
      let scan_start = if n > 288 { n - 288 } else { 0 }
      let max_pos = n - @sm3.SM3_DIGEST_SIZE - 1
      for pos = scan_start; pos <= max_pos; pos = pos + 1 {
        let is_match = @ct.ct_eq_u32(pos.reinterpret_as_uint(), pt_len_u)
        for k = 0; k < @sm3.SM3_DIGEST_SIZE; k = k + 1 {
          received_mac[k] = @ct.ct_select_byte(
            is_match,
            dec[pos + k],
            received_mac[k],
          )
        }
      }
      // Compute expected HMAC-SM3 and equalize SM3 compression blocks (Lucky13 mitigation)
      let aad = build_aad(self.seq, rec.content_type, pt_len)
      let expected_mac = @sm3.hmac_sm3_parts(mac_key, [aad[:], dec[:pt_len]])
      let max_hash_len = 13 + max_pos
      let actual_hash_len = 13 + pt_len
      let max_blocks = (max_hash_len + 136) / @sm3.SM3_BLOCK_SIZE
      let actual_blocks = (actual_hash_len + 136) / @sm3.SM3_BLOCK_SIZE
      let extra_blocks = max_blocks - actual_blocks
      if extra_blocks > 0 {
        let dummy = @sm3.Sm3::new()
        let zero_block = Bytes::make(@sm3.SM3_BLOCK_SIZE, b'\x00')
        for _b = 0; _b < extra_blocks; _b = _b + 1 {
          dummy.update(zero_block)
        }
        ignore(dummy)
      }
      let mac_ok : UInt32 = if @ct.ct_eq(
          expected_mac,
          Bytes::from_array(received_mac),
        ) {
        1U
      } else {
        0U
      }
      if (pad_good & mac_ok) == 0U {
        raise BadRecordMac
      }
      if pt_len > MAX_PLAINTEXT_LEN {
        raise RecordOverflow(pt_len)
      }
      let out = FixedArray::make(pt_len, b'\x00')
      for i = 0; i < pt_len; i = i + 1 {
        out[i] = dec[i]
      }
      Bytes::from_array(out)
    }
    Sm4Gcm(sm4, implicit_iv) => {
      let payload_len = rec.payload.length()
      if payload_len < GCM_EXPLICIT_NONCE_LEN + GCM_TAG_LEN {
        raise BadRecordMac
      }
      let ct_len = payload_len - GCM_EXPLICIT_NONCE_LEN - GCM_TAG_LEN
      let nonce = FixedArray::make(GCM_NONCE_LEN, b'\x00')
      for i = 0; i < GCM_IMPLICIT_IV_LEN; i = i + 1 {
        nonce[i] = implicit_iv[i]
      }
      for i = 0; i < GCM_EXPLICIT_NONCE_LEN; i = i + 1 {
        nonce[GCM_IMPLICIT_IV_LEN + i] = rec.payload[i]
      }
      let ct = FixedArray::make(ct_len, b'\x00')
      for i = 0; i < ct_len; i = i + 1 {
        ct[i] = rec.payload[GCM_EXPLICIT_NONCE_LEN + i]
      }
      let tag = FixedArray::make(GCM_TAG_LEN, b'\x00')
      for i = 0; i < GCM_TAG_LEN; i = i + 1 {
        tag[i] = rec.payload[GCM_EXPLICIT_NONCE_LEN + ct_len + i]
      }
      let aad = build_aad(self.seq, rec.content_type, ct_len)
      let pt = sm4.gcm_decrypt(
        Bytes::from_array(nonce),
        aad,
        Bytes::from_array(ct),
        Bytes::from_array(tag),
      ) catch {
        _ => raise BadRecordMac
      }
      if pt.length() > MAX_PLAINTEXT_LEN {
        raise RecordOverflow(pt.length())
      }
      pt
    }
  }
  self.seq = self.seq + 1UL
  plaintext
}
