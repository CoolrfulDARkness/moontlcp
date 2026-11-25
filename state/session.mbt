///|
/// Session cache for TLCP 1.1 Session ID abbreviated handshakes (GM/T 0024 §6.4.1).

///|
/// Exportable TLCP session state used for Session ID resumption.
#derive(Debug, Eq)
pub(all) struct ResumedSession {
  session_id : Bytes
  cipher_suite : @handshake.CipherSuite
  master_secret : Bytes
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
/// Inserts or updates a session entry keyed by `session.session_id`.
pub fn SessionStore::put(self : SessionStore, session : ResumedSession) -> Unit {
  if session.session_id.length() == 0 {
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
