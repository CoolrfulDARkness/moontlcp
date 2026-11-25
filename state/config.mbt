///|
/// Client and Server configuration types for TLCP 1.1 connections.

///|
/// Returns the default ordered list of all 4 GM/T 0024-2023 cipher suites
/// (preferring ECDHE and SM4-GCM AEAD first).
pub fn default_cipher_suites() -> Array[@handshake.CipherSuite] {
  [
    @handshake.EccSm4GcmSm3,
    @handshake.EccSm4CbcSm3,
    @handshake.EcdheSm4GcmSm3,
    @handshake.EcdheSm4CbcSm3,
  ]
}

///|
/// Configuration for a TLCP 1.1 client connection.
pub(all) struct ClientConfig {
  trust_anchors : Array[@x509.Certificate]
  cipher_suites : Array[@handshake.CipherSuite]
  /// Optional client dual certificates and private keys:
  /// `(sign_cert, sign_priv, enc_cert, enc_priv)`. Required for mTLCP and ECDHE suites.
  client_certs : (
    @x509.Certificate,
    @sm2.PrivateKey,
    @x509.Certificate,
    @sm2.PrivateKey,
  )?
  resume_session : ResumedSession?
  seed : Bytes
}

///|
/// Creates a `ClientConfig` with default cipher suites, no client certs, and no
/// resumed session.
pub fn ClientConfig::new(
  trust_anchors : Array[@x509.Certificate],
  seed : Bytes,
) -> ClientConfig {
  {
    trust_anchors,
    cipher_suites: default_cipher_suites(),
    client_certs: None,
    resume_session: None,
    seed,
  }
}

///|
/// Configuration for a TLCP 1.1 server connection (GM/T 0024 dual certificates).
pub(all) struct ServerConfig {
  sign_cert : @x509.Certificate
  sign_priv : @sm2.PrivateKey
  enc_cert : @x509.Certificate
  enc_priv : @sm2.PrivateKey
  cipher_suites : Array[@handshake.CipherSuite]
  require_client_cert : Bool
  client_trust_anchors : Array[@x509.Certificate]
  session_store : SessionStore?
  seed : Bytes
}

///|
/// Creates a `ServerConfig` with default cipher suites, optional mTLCP disabled,
/// and no session store.
pub fn ServerConfig::new(
  sign_cert : @x509.Certificate,
  sign_priv : @sm2.PrivateKey,
  enc_cert : @x509.Certificate,
  enc_priv : @sm2.PrivateKey,
  seed : Bytes,
) -> ServerConfig {
  {
    sign_cert,
    sign_priv,
    enc_cert,
    enc_priv,
    cipher_suites: default_cipher_suites(),
    require_client_cert: false,
    client_trust_anchors: [],
    session_store: None,
    seed,
  }
}
