///|
/// Pure MoonBit, zero-FFI, Sans-I/O GM/T 0024-2023 (GB/T 38636-2020) TLCP 1.1
/// protocol stack root facade package (`CoolrfulDARkness/moontlcp`).
///
/// Re-exports ergonomic entry points for national standard cryptography
/// (SM2/SM3/SM4), X.509 v3 dual-certificate verification, and Sans-I/O TLCP
/// client/server sessions.

// ============================================================================
// Cryptography Entry Points (GB/T 32905 / 32907 / 32918 & RFC 8998)
// ============================================================================

///|
/// Computes the 32-byte GB/T 32905-2016 SM3 digest of `data`.
pub fn sm3_hash(data : Bytes) -> Bytes {
  @sm3.sm3(data)
}

///|
/// Computes RFC 2104 HMAC-SM3 (32 bytes) over `data` using `key`.
pub fn hmac_sm3(key : Bytes, data : Bytes) -> Bytes {
  @sm3.hmac_sm3(key, data)
}

///|
/// Computes GM/T 0024-2023 §6.3 TLCP PRF (`P_SM3(secret, label || seed)`).
pub fn tlcp_prf(
  secret : Bytes,
  label : Bytes,
  seed : Bytes,
  out_len : Int32,
) -> Bytes {
  @sm3.tlcp_prf(secret, label, seed, out_len)
}

///|
/// Encrypts `plaintext` with RFC 8998 / GM/T 0024-2023 SM4-GCM AEAD.
/// Returns `(ciphertext, tag)` where `tag.length() == 16`.
pub fn sm4_gcm_encrypt(
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  plaintext : Bytes,
) -> (Bytes, Bytes) raise @sm4.Sm4Error {
  let sm4 = @sm4.Sm4Key::new(key)
  sm4.gcm_encrypt(iv, aad, plaintext)
}

///|
/// Authenticates and decrypts an SM4-GCM ciphertext in constant time.
pub fn sm4_gcm_decrypt(
  key : Bytes,
  iv : Bytes,
  aad : Bytes,
  ciphertext : Bytes,
  tag : Bytes,
) -> Bytes raise @sm4.Sm4Error {
  let sm4 = @sm4.Sm4Key::new(key)
  sm4.gcm_decrypt(iv, aad, ciphertext, tag)
}

///|
/// Deterministically signs `(id, msg)` with SM2 (GB/T 32918.2) and returns an
/// ASN.1 DER `SEQUENCE { r, s }` signature.
pub fn sm2_sign_der(
  priv_key : @sm2.PrivateKey,
  id : Bytes,
  msg : Bytes,
) -> Bytes raise @sm2.Sm2Error {
  @sm2.sign_der(priv_key, id, msg)
}

///|
/// Verifies an ASN.1 DER SM2 signature over `(id, msg)`.
pub fn sm2_verify_der(
  pub_key : @sm2.PublicKey,
  id : Bytes,
  msg : Bytes,
  sig_der : Bytes,
) -> Bool {
  @sm2.verify_der(pub_key, id, msg, sig_der)
}

///|
/// Encrypts `plaintext` using SM2 (GB/T 32918.4) into strict ASN.1 DER `SM2Cipher`.
pub fn sm2_encrypt_asn1(
  pub_key : @sm2.PublicKey,
  plaintext : Bytes,
  seed : Bytes,
) -> Bytes raise @sm2.Sm2Error {
  @sm2.encrypt_asn1(pub_key, plaintext, seed)
}

///|
/// Decrypts and authenticates an ASN.1 DER `SM2Cipher` in constant time.
pub fn sm2_decrypt_asn1(
  priv_key : @sm2.PrivateKey,
  der_cipher : Bytes,
) -> Bytes raise @sm2.Sm2Error {
  @sm2.decrypt_asn1(priv_key, der_cipher)
}

// ============================================================================
// X.509 v3 & TLCP Dual-Certificate Entry Points
// ============================================================================

///|
/// Deterministically generates a full GM SM2 X.509 v3 test PKI (Root CA,
/// server signing/encryption dual certs, and client signing/encryption dual certs).
pub fn generate_test_pki(seed : Bytes) -> @x509.TestPki raise @x509.X509Error {
  @x509.generate_test_pki(seed)
}

///|
/// Strictly parses a DER-encoded SM2 X.509 v3 certificate.
pub fn parse_cert_der(der : Bytes) -> @x509.Certificate raise @x509.X509Error {
  @x509.Certificate::from_der(der)
}

///|
/// Parses all PEM-encoded SM2 X.509 v3 certificates from `pem`.
pub fn parse_certs_pem(
  pem : String,
) -> Array[@x509.Certificate] raise @x509.X509Error {
  @x509.Certificate::from_pem(pem)
}

///|
/// Parses and verifies a GM/T 0024-2023 dual-certificate chain
/// (`[sign_cert, enc_cert, ...intermediates]`) against `trust_anchors`.
pub fn verify_dual_certs(
  der_chain : Array[Bytes],
  trust_anchors : Array[@x509.Certificate],
) -> @x509.DualCertBundle raise @x509.X509Error {
  @x509.parse_and_verify_dual_certs(der_chain, trust_anchors)
}

// ============================================================================
// Sans-I/O TLCP 1.1 Session Entry Points
// ============================================================================

///|
/// Creates a new Sans-I/O TLCP 1.1 client connection.
pub fn new_client(config : @state.ClientConfig) -> @state.ClientConn {
  @state.ClientConn::new(config)
}

///|
/// Creates a new Sans-I/O TLCP 1.1 server connection.
pub fn new_server(config : @state.ServerConfig) -> @state.ServerConn {
  @state.ServerConn::new(config)
}

///|
/// Creates an empty in-memory `SessionStore` for TLCP Session ID resumption.
pub fn new_session_store() -> @state.SessionStore {
  @state.SessionStore::new()
}

///|
/// Returns the default ordered list of all 4 GM/T 0024-2023 cipher suites.
pub fn default_cipher_suites() -> Array[@handshake.CipherSuite] {
  @state.default_cipher_suites()
}

///|
/// Drives a `ClientConn` and `ServerConn` through a complete TLCP 1.1 handshake
/// over an in-memory byte channel.
///
/// Returns `(client_bytes_sent, server_bytes_sent)` once both peers are
/// established, or raises `@state.StateError` if either side fails.
pub fn run_handshake_loop(
  client : @state.ClientConn,
  server : @state.ServerConn,
) -> (Int32, Int32) raise @state.StateError {
  let mut client_sent = 0
  let mut server_sent = 0
  let mut to_server = client.start_handshake()
  for _round = 0; _round < 16; _round = _round + 1 {
    if to_server.length() > 0 {
      client_sent = client_sent + to_server.length()
      ignore(server.feed(to_server[:]))
      to_server = b""
    }
    let to_client = server.take_outbound()
    if to_client.length() > 0 {
      server_sent = server_sent + to_client.length()
      ignore(client.feed(to_client[:]))
    }
    to_server = client.take_outbound()
    if to_server.length() == 0 &&
      client.is_established() &&
      server.is_established() {
      return (client_sent, server_sent)
    }
  }
  if !client.is_established() {
    ignore(client.write_app_data(b"\x00"))
  }
  if !server.is_established() {
    ignore(server.write_app_data(b"\x00"))
  }
  (client_sent, server_sent)
}
