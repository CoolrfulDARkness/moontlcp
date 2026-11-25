///|
/// Events, error types, deterministic SM3 DRBG, and shared helpers for the
/// Sans-I/O TLCP 1.1 state machine.

///|
/// High-level events produced by `ClientConn::feed` and `ServerConn::feed`.
#derive(Debug, Eq)
pub(all) enum Event {
  HandshakeComplete
  ApplicationData(Bytes)
  PeerClosed
  WarningAlert(@handshake.AlertDescription)
}

///|
/// Fail-closed state machine errors. Whenever a protocol, certificate, record,
/// or cryptographic error occurs, the connection queues a corresponding Fatal
/// Alert into its outbound buffer and permanently transitions to `Failed`.
#derive(Debug, Eq)
pub suberror StateError {
  ProtocolError(@handshake.AlertDescription, String)
  RecordError(String)
  CertificateError(String)
  CryptoError(String)
  InvalidState(String)
}

///|
/// Deterministic SM3-based counter DRBG derived from caller-supplied `seed`.
struct Prng {
  seed : Bytes
  mut counter : UInt64
}

///|
fn Prng::new(seed : Bytes) -> Prng {
  let effective_seed = if seed.length() == 0 {
    b"moontlcp-default-seed"
  } else {
    seed
  }
  { seed: effective_seed, counter: 0UL, }
}

///|
fn encode_u64_be(v : UInt64) -> Bytes {
  let out = FixedArray::make(8, b'\x00')
  out[0] = ((v >> 56) & 0xFFUL).to_byte()
  out[1] = ((v >> 48) & 0xFFUL).to_byte()
  out[2] = ((v >> 40) & 0xFFUL).to_byte()
  out[3] = ((v >> 32) & 0xFFUL).to_byte()
  out[4] = ((v >> 24) & 0xFFUL).to_byte()
  out[5] = ((v >> 16) & 0xFFUL).to_byte()
  out[6] = ((v >> 8) & 0xFFUL).to_byte()
  out[7] = (v & 0xFFUL).to_byte()
  Bytes::from_array(out)
}

///|
fn Prng::next_bytes(self : Prng, domain : Bytes, len : Int32) -> Bytes {
  let ctr = encode_u64_be(self.counter)
  self.counter = self.counter + 1UL
  @sm3.tlcp_prf(self.seed, domain, ctr, len)
}

///|
/// Returns the per-record explicit IV/nonce:
/// - `SM4-GCM` (RFC 5288 §3): big-endian 64-bit record sequence number (strictly
///   unique across 2^64 records with zero extra PRF overhead).
/// - `SM4-CBC` (RFC 5246 §6.2.3.2): unpredictable 16-byte DRBG explicit IV.
fn Prng::next_explicit_iv(
  self : Prng,
  suite : @handshake.CipherSuite?,
  seq : UInt64,
) -> Bytes {
  match suite {
    None => b""
    Some(s) =>
      if s.is_gcm() {
        encode_u64_be(seq)
      } else {
        self.next_bytes(b"tlcp-cbc-iv", @sm4.SM4_BLOCK_SIZE)
      }
  }
}

///|
fn append_bytes(dst : Array[Byte], src : Bytes) -> Unit {
  for i = 0; i < src.length(); i = i + 1 {
    dst.push(src[i])
  }
}

///|
fn append_view(dst : Array[Byte], src : BytesView) -> Unit {
  for i = 0; i < src.length(); i = i + 1 {
    dst.push(src[i])
  }
}

///|
fn drain_buffer(buf : Array[Byte]) -> Bytes {
  if buf.length() == 0 {
    return b""
  }
  let out = Bytes::from_array(buf)
  buf.clear()
  out
}

///|
fn consume_prefix(buf : Array[Byte], count : Int32) -> Unit {
  if count <= 0 {
    return
  }
  let rem = buf.length() - count
  if rem <= 0 {
    buf.clear()
    return
  }
  let next : Array[Byte] = Array(capacity=rem)
  for i = count; i < buf.length(); i = i + 1 {
    next.push(buf[i])
  }
  buf.clear()
  for i = 0; i < next.length(); i = i + 1 {
    buf.push(next[i])
  }
}

///|
fn make_cipher_state(
  suite : @handshake.CipherSuite,
  kb : @handshake.KeyBlock,
  is_client_write : Bool,
) -> @record.CipherState raise StateError {
  if suite.is_gcm() {
    let key = if is_client_write {
      kb.client_write_key
    } else {
      kb.server_write_key
    }
    let iv = if is_client_write {
      kb.client_write_iv
    } else {
      kb.server_write_iv
    }
    @record.CipherState::new_gcm(key, iv) catch {
      _ => raise CryptoError("failed to initialize SM4-GCM cipher state")
    }
  } else {
    let key = if is_client_write {
      kb.client_write_key
    } else {
      kb.server_write_key
    }
    let mac_key = if is_client_write {
      kb.client_mac_key
    } else {
      kb.server_mac_key
    }
    @record.CipherState::new_cbc(key, mac_key) catch {
      _ => raise CryptoError("failed to initialize SM4-CBC cipher state")
    }
  }
}

///|
fn record_err_to_alert(
  err : @record.RecordError,
) -> (@handshake.AlertDescription, String) {
  match err {
    @record.UnsupportedVersion(_, _) =>
      (@handshake.ProtocolVersion, "unsupported TLCP record version")
    @record.RecordOverflow(_) =>
      (@handshake.RecordOverflow, "TLCP record overflow")
    @record.BadRecordMac => (@handshake.BadRecordMac, "bad record MAC")
    @record.InvalidContentType(_) =>
      (@handshake.UnexpectedMessage, "invalid record content type")
    @record.SequenceOverflow =>
      (@handshake.InternalError, "record sequence number overflow")
    @record.CryptoError(msg) => (@handshake.InternalError, msg)
    @record.Incomplete => (@handshake.DecodeError, "incomplete record")
  }
}

///|
fn handshake_err_to_alert(
  err : @handshake.HandshakeError,
) -> (@handshake.AlertDescription, String) {
  match err {
    @handshake.InvalidVersion(_, _) =>
      (@handshake.ProtocolVersion, "invalid TLCP handshake version")
    @handshake.UnsupportedCipherSuite =>
      (@handshake.HandshakeFailure, "unsupported cipher suite")
    @handshake.InvalidMessageType(_) =>
      (@handshake.UnexpectedMessage, "invalid handshake message type")
    @handshake.InvalidLength =>
      (@handshake.DecodeError, "invalid handshake message length")
    @handshake.DecodeError(msg) => (@handshake.DecodeError, msg)
    @handshake.Incomplete =>
      (@handshake.DecodeError, "incomplete handshake message")
  }
}

///|
fn x509_err_to_alert(
  err : @x509.X509Error,
) -> (@handshake.AlertDescription, String) {
  match err {
    @x509.ChainVerificationFailed(msg) => (@handshake.UnknownCa, msg)
    @x509.NotCa => (@handshake.BadCertificate, "issuer certificate is not a CA")
    @x509.InvalidSignature =>
      (@handshake.BadCertificate, "certificate signature verification failed")
    @x509.BadKeyUsage(msg) => (@handshake.BadCertificate, msg)
    @x509.DualCertMismatch(msg) => (@handshake.BadCertificate, msg)
    @x509.InvalidCertCount(n) =>
      (
        @handshake.BadCertificate,
        "invalid dual-certificate count: " + n.to_string(),
      )
    @x509.UnsupportedVersion =>
      (@handshake.UnsupportedCertificate, "unsupported X.509 version")
    @x509.UnsupportedAlgorithm(alg) =>
      (@handshake.UnsupportedCertificate, "unsupported algorithm: " + alg)
    @x509.InvalidPublicKey =>
      (@handshake.BadCertificate, "invalid SM2 public key in certificate")
    @x509.DerError(msg) => (@handshake.BadCertificate, "DER error: " + msg)
  }
}

///|
fn sm2_err_to_msg(err : @sm2.Sm2Error) -> String {
  match err {
    @sm2.InvalidPrivateKey => "invalid SM2 private key"
    @sm2.InvalidPublicKey => "invalid SM2 public key"
    @sm2.InvalidSignature => "invalid SM2 signature"
    @sm2.InvalidCiphertext => "invalid SM2 ciphertext"
    @sm2.DecryptionFailed => "SM2 decryption failed"
    @sm2.KeyExchangeFailed => "SM2 key exchange failed"
    @sm2.InvalidLength(n) => "invalid SM2 length: " + n.to_string()
  }
}

///|
fn bytes_contains(haystack : Bytes, needle : Byte) -> Bool {
  for i = 0; i < haystack.length(); i = i + 1 {
    if haystack[i] == needle {
      return true
    }
  }
  false
}
