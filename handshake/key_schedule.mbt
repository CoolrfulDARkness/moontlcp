///|
/// GM/T 0024-2023 (GB/T 38636-2020) §6.3 TLCP 1.1 Key Schedule & Handshake Transcript.

///|
const MASTER_SECRET_LEN : Int32 = 48

///|
const CBC_KEY_BLOCK_LEN : Int32 = 128

///|
const GCM_KEY_BLOCK_LEN : Int32 = 40

///|
fn concat_two(a : Bytes, b : Bytes) -> Bytes {
  let out = FixedArray::make(a.length() + b.length(), b'\x00')
  for i = 0; i < a.length(); i = i + 1 {
    out[i] = a[i]
  }
  for i = 0; i < b.length(); i = i + 1 {
    out[a.length() + i] = b[i]
  }
  Bytes::from_array(out)
}

///|
fn copy_range(src : Bytes, off : Int32, len : Int32) -> Bytes {
  let out = FixedArray::make(len, b'\x00')
  for i = 0; i < len; i = i + 1 {
    out[i] = src[off + i]
  }
  Bytes::from_array(out)
}

///|
/// Derives the 48-byte TLCP 1.1 `master_secret` via `P_SM3`:
/// `PRF(pre_master_secret, "master secret", client_random || server_random)[0..47]`.
pub fn derive_master_secret(
  pre_master_secret : Bytes,
  client_random : Bytes,
  server_random : Bytes,
) -> Bytes {
  let seed = concat_two(client_random, server_random)
  @sm3.tlcp_prf(pre_master_secret, b"master secret", seed, MASTER_SECRET_LEN)
}

///|
/// Partitioned symmetric key material derived from `master_secret`.
#derive(Debug, Eq)
pub(all) struct KeyBlock {
  client_mac_key : Bytes
  server_mac_key : Bytes
  client_write_key : Bytes
  server_write_key : Bytes
  client_write_iv : Bytes
  server_write_iv : Bytes
}

///|
/// Derives the TLCP 1.1 `KeyBlock` via `P_SM3`:
/// `PRF(master_secret, "key expansion", server_random || client_random)`.
///
/// - CBC suites: 32/32/16/16/16/16 = 128 bytes.
/// - GCM suites: 0/0/16/16/4/4 = 40 bytes.
pub fn derive_key_block(
  master_secret : Bytes,
  server_random : Bytes,
  client_random : Bytes,
  suite : CipherSuite,
) -> KeyBlock {
  let seed = concat_two(server_random, client_random)
  if suite.is_gcm() {
    let raw = @sm3.tlcp_prf(
      master_secret,
      b"key expansion",
      seed,
      GCM_KEY_BLOCK_LEN,
    )
    {
      client_mac_key: b"",
      server_mac_key: b"",
      client_write_key: copy_range(raw, 0, 16),
      server_write_key: copy_range(raw, 16, 16),
      client_write_iv: copy_range(raw, 32, 4),
      server_write_iv: copy_range(raw, 36, 4),
    }
  } else {
    let raw = @sm3.tlcp_prf(
      master_secret,
      b"key expansion",
      seed,
      CBC_KEY_BLOCK_LEN,
    )
    {
      client_mac_key: copy_range(raw, 0, 32),
      server_mac_key: copy_range(raw, 32, 32),
      client_write_key: copy_range(raw, 64, 16),
      server_write_key: copy_range(raw, 80, 16),
      client_write_iv: copy_range(raw, 96, 16),
      server_write_iv: copy_range(raw, 112, 16),
    }
  }
}

///|
/// Computes the 12-byte `Finished.verify_data` via `P_SM3`:
/// `PRF(master_secret, "client finished" | "server finished", transcript_hash)[0..11]`.
pub fn compute_verify_data(
  master_secret : Bytes,
  is_client : Bool,
  transcript_hash : Bytes,
) -> Bytes {
  let label = if is_client { b"client finished" } else { b"server finished" }
  @sm3.tlcp_prf(master_secret, label, transcript_hash, 12)
}

///|
/// Rolling SM3 handshake transcript accumulator that also retains the raw
/// message byte stream (required for SM2 `CertificateVerify` signing).
pub struct Transcript {
  hasher : @sm3.Sm3
  raw : Array[Byte]
}

///|
/// Creates an empty `Transcript`.
pub fn Transcript::new() -> Transcript {
  { hasher: @sm3.Sm3::new(), raw: [], }
}

///|
/// Appends encoded handshake message bytes to both the rolling SM3 hash and
/// the raw transcript buffer.
pub fn Transcript::update(self : Transcript, data : Bytes) -> Unit {
  self.hasher.update(data)
  for i = 0; i < data.length(); i = i + 1 {
    self.raw.push(data[i])
  }
}

///|
/// Returns the 32-byte SM3 digest of all messages fed so far without mutating state.
pub fn Transcript::hash(self : Transcript) -> Bytes {
  self.hasher.finalize()
}

///|
/// Returns a copy of all raw handshake bytes accumulated so far.
pub fn Transcript::raw_bytes(self : Transcript) -> Bytes {
  Bytes::from_array(self.raw)
}
