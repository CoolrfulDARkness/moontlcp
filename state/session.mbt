///|
/// Session cache for TLCP 1.1 Session ID abbreviated handshakes (GM/T 0024 §6.4.1).

///|
/// Exportable TLCP session state used for Session ID resumption.
/// Retains authenticated `peer_certs` (if any) so mTLCP servers never resume
/// an unauthenticated session when `require_client_cert` is enabled.
#derive(Debug, Eq)
pub(all) struct ResumedSession {
  session_id : Bytes
  cipher_suite : @handshake.CipherSuite
  master_secret : Bytes
  peer_certs : @x509.DualCertBundle?
}

///|
fn is_valid_resumed_session(session : ResumedSession) -> Bool {
  session.session_id.length() > 0 &&
  session.session_id.length() <= 32 &&
  session.master_secret.length() == 48
}

///|
/// In-memory server-side session store mapping `session_id` to `ResumedSession`.
pub struct SessionStore {
  entries : Array[ResumedSession]
}

///|
/// Creates an empty `SessionStore`.
pub fn SessionStore::new() -> SessionStore {
  { entries: [], }
}

///|
/// Inserts or updates a validated session entry keyed by `session.session_id`.
/// Invalid entries (`session_id` not in `1..=32` bytes or `master_secret != 48` bytes)
/// are ignored.
pub fn SessionStore::put(self : SessionStore, session : ResumedSession) -> Unit {
  if !is_valid_resumed_session(session) {
    return
  }
  for i = 0; i < self.entries.length(); i = i + 1 {
    if self.entries[i].session_id == session.session_id {
      self.entries[i] = session
      return
    }
  }
  self.entries.push(session)
}

///|
/// Looks up a cached session by `session_id`.
pub fn SessionStore::get(
  self : SessionStore,
  session_id : Bytes,
) -> ResumedSession? {
  if session_id.length() == 0 {
    return None
  }
  for i = 0; i < self.entries.length(); i = i + 1 {
    if self.entries[i].session_id == session_id {
      return Some(self.entries[i])
    }
  }
  None
}

///|
/// Removes a session entry by `session_id`.
pub fn SessionStore::remove(self : SessionStore, session_id : Bytes) -> Unit {
  let mut idx = -1
  for i = 0; i < self.entries.length(); i = i + 1 {
    if self.entries[i].session_id == session_id {
      idx = i
      break
    }
  }
  if idx >= 0 {
    ignore(self.entries.remove(idx))
  }
}

///|
/// Returns the number of cached sessions.
pub fn SessionStore::len(self : SessionStore) -> Int32 {
  self.entries.length()
}
