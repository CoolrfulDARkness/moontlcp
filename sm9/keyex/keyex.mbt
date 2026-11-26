///|
/// Maximum allowed KDF output length (16 MiB) to prevent OOM DoS.
pub const MAX_KDF_LEN : Int32 = 16_777_216

///|
/// Output of the SM9 key exchange responder (User B, GB/T 38635.3-2020 §6.2).
/// - `sk`: derived shared secret key `SK_B` of length `klen` bytes.
/// - `s_b`: key confirmation hash `S_B` (tag `0x82`, 32 bytes) sent from B to A.
/// - `s_2`: expected confirmation hash `S_2` (tag `0x83`, 32 bytes) used by B to verify `S_A` from A.
#derive(Debug)
pub struct ResponderResult {
  sk : Bytes
  s_b : Bytes
  s_2 : Bytes
}

///|
/// Constant-time equality comparison across all byte fields of `ResponderResult`
/// without short-circuiting.
pub fn ResponderResult::ct_eq(
  self : ResponderResult,
  other : ResponderResult,
) -> Bool {
  let sk_eq = @field.ct_mask(@sm3.ct_eq_bytes(self.sk, other.sk))
  let sb_eq = @field.ct_mask(@sm3.ct_eq_bytes(self.s_b, other.s_b))
  let s2_eq = @field.ct_mask(@sm3.ct_eq_bytes(self.s_2, other.s_2))
  (sk_eq & sb_eq & s2_eq) != 0UL
}

///|
pub impl Eq for ResponderResult with fn equal(self, other) {
  self.ct_eq(other)
}

///|
/// Output of the SM9 key exchange initiator (User A, GB/T 38635.3-2020 §6.2).
/// - `sk`: derived shared secret key `SK_A` of length `klen` bytes.
/// - `s_a`: key confirmation hash `S_A` (tag `0x83`, 32 bytes) sent from A to B.
/// - `s_1`: locally computed confirmation hash `S_1` (tag `0x82`, 32 bytes) matching `S_B` from B.
#derive(Debug)
pub struct InitiatorResult {
  sk : Bytes
  s_a : Bytes
  s_1 : Bytes
}

///|
/// Constant-time equality comparison across all byte fields of `InitiatorResult`
/// without short-circuiting.
pub fn InitiatorResult::ct_eq(
  self : InitiatorResult,
  other : InitiatorResult,
) -> Bool {
  let sk_eq = @field.ct_mask(@sm3.ct_eq_bytes(self.sk, other.sk))
  let sa_eq = @field.ct_mask(@sm3.ct_eq_bytes(self.s_a, other.s_a))
  let s1_eq = @field.ct_mask(@sm3.ct_eq_bytes(self.s_1, other.s_1))
  (sk_eq & sa_eq & s1_eq) != 0UL
}

///|
pub impl Eq for InitiatorResult with fn equal(self, other) {
  self.ct_eq(other)
}

///|
/// Constant-time check returning `true` iff every byte in `data` is `0x00`.
fn is_all_zero(data : BytesView) -> Bool {
  let mut acc = 0
  for i = 0; i < data.length(); i = i + 1 {
    acc = acc | data[i].to_int()
  }
  acc == 0
}

///|
/// Concatenates byte slices into a single `Bytes` buffer.
fn concat_bytes(parts : Array[BytesView]) -> Bytes {
  let mut total = 0
  for i = 0; i < parts.length(); i = i + 1 {
    total = total + parts[i].length()
  }
  let out : FixedArray[Byte] = FixedArray::make(total, b'\x00')
  let mut off = 0
  for i = 0; i < parts.length(); i = i + 1 {
    let part = parts[i]
    let len = part.length()
    for j = 0; j < len; j = j + 1 {
      out[off + j] = part[j]
    }
    off = off + len
  }
  Bytes::makei(total, fn(i) { out[i] })
}

///|
/// Validates that a `G1Affine` point is finite and lies on `E(Fp)` (cofactor `h1 = 1`).
fn validate_g1_point(pt : @ec.G1Affine, name : String) -> Result[Unit, String] {
  if pt.is_infinity() {
    return Err("\{name} must not be the point at infinity")
  }
  if !pt.is_on_curve() {
    return Err("\{name} is not on curve E(Fp)")
  }
  Ok(())
}

///|
/// Validates that a `G2Affine` point is finite, lies on `E'(Fp2)`, and is in the prime-order
/// `G2` subgroup (`[N]Q == O`).
fn validate_g2_point(pt : @ec.G2Affine, name : String) -> Result[Unit, String] {
  if pt.is_infinity() {
    return Err("\{name} must not be the point at infinity")
  }
  if !pt.is_on_curve() {
    return Err("\{name} is not on twist curve E'(Fp2)")
  }
  if !pt.is_in_subgroup() {
    return Err("\{name} is not in the G2 prime-order subgroup")
  }
  Ok(())
}

///|
/// Evaluates the BN256 optimal R-ate pairing `e(q, p)` on validated affine points.
fn pair_g2_g1(q : @ec.G2Affine, p : @ec.G1Affine) -> @field.Fp12 {
  @pairing.pair_coords(q.x(), q.y(), p.x(), p.y())
}

///|
/// Computes the inner confirmation digest:
/// `SM3(g2 || g3 || ID_A || ID_B || R_A_raw || R_B_raw)` (GB/T 38635.3-2020 §6.2).
/// Note: `R_A_raw` and `R_B_raw` are strictly 64-byte raw coordinates (`x || y`, no `0x04` prefix).
fn compute_inner_hash(
  g2_bytes : BytesView,
  g3_bytes : BytesView,
  id_a : BytesView,
  id_b : BytesView,
  ra_raw : BytesView,
  rb_raw : BytesView,
) -> Bytes {
  let hasher = @sm3.Sm3::new()
  hasher.update(g2_bytes)
  hasher.update(g3_bytes)
  hasher.update(id_a)
  hasher.update(id_b)
  hasher.update(ra_raw)
  hasher.update(rb_raw)
  hasher.finalize()
}

///|
/// Computes a tagged confirmation hash `SM3(tag || g1 || inner)`:
/// - `tag = 0x82` for `S_B` / `S_1`
/// - `tag = 0x83` for `S_2` / `S_A`
fn compute_confirm_hash(
  tag : Byte,
  g1_bytes : BytesView,
  inner : BytesView,
) -> Bytes {
  let hasher = @sm3.Sm3::new()
  hasher.update_byte(tag)
  hasher.update(g1_bytes)
  hasher.update(inner)
  hasher.finalize()
}

///|
/// Generates an SM9 key exchange ephemeral point `R = [r]Q_peer` (GB/T 38635.3-2020 §6.2 Steps A1-A3 / B1-B3).
///
/// Computes `Q_peer = [H1(peer_id || hid, N)]P1 + P_pub-e` and `R = [r]Q_peer`.
/// Returns `Err` if `p_pub_e` is invalid/infinity, `r == 0`, or the resulting point is infinity.
pub fn generate_ephemeral(
  p_pub_e : @ec.G1Affine,
  peer_id : BytesView,
  r : @field.Fn,
  hid~ : Byte = b'\x02',
) -> Result[@ec.G1Affine, String] {
  match validate_g1_point(p_pub_e, "p_pub_e") {
    Err(msg) => return Err(msg)
    Ok(_) => ()
  }
  if r.is_zero() {
    return Err("ephemeral scalar r must be non-zero")
  }
  let id_len = peer_id.length()
  let z = Bytes::makei(id_len + 1, fn(i) {
    if i < id_len {
      peer_id[i]
    } else {
      hid
    }
  })
  let h1_bytes = @sm3.h1(z, @field.order_n.to_be_bytes())
  let h1 = match @field.Fn::from_be_bytes_nonzero(h1_bytes) {
    Some(v) => v
    None => return Err("H1 returned zero scalar")
  }
  let q_peer = @ec.G1Affine::generator().scalar_mul_fn(h1).add_mixed(p_pub_e)
  if q_peer.is_identity() {
    return Err("derived peer public point Q_peer is at infinity")
  }
  let r_point = q_peer.scalar_mul_fn(r).to_affine()
  if r_point.is_infinity() {
    return Err("ephemeral point R is at infinity")
  }
  Ok(r_point)
}

///|
/// Executes the SM9 key exchange responder steps (User B, GB/T 38635.3-2020 §6.2 Steps B5-B8).
///
/// Computes:
/// - `g1 = e(de_b, r_a_point)`
/// - `g2 = e(P2, p_pub_e)^{r_b}`
/// - `g3 = g1^{r_b}`
/// - `SK_B = KDF(id_a || id_b || R_A_raw || R_B_raw || g1 || g2 || g3, klen)`
/// - `S_B = SM3(0x82 || g1 || SM3(g2 || g3 || id_a || id_b || R_A_raw || R_B_raw))`
/// - `S_2 = SM3(0x83 || g1 || SM3(g2 || g3 || id_a || id_b || R_A_raw || R_B_raw))`
pub fn responder_exchange(
  p_pub_e : @ec.G1Affine,
  id_a : BytesView,
  id_b : BytesView,
  de_b : @ec.G2Affine,
  r_b : @field.Fn,
  r_a_point : @ec.G1Affine,
  r_b_point : @ec.G1Affine,
  klen : Int32,
) -> Result[ResponderResult, String] {
  if klen <= 0 || klen > MAX_KDF_LEN {
    return Err("klen must be in [1, MAX_KDF_LEN]")
  }
  if r_b.is_zero() {
    return Err("ephemeral scalar r_b must be non-zero")
  }
  match validate_g1_point(p_pub_e, "p_pub_e") {
    Err(msg) => return Err(msg)
    Ok(_) => ()
  }
  match validate_g2_point(de_b, "de_b") {
    Err(msg) => return Err(msg)
    Ok(_) => ()
  }
  match validate_g1_point(r_a_point, "r_a_point") {
    Err(msg) => return Err(msg)
    Ok(_) => ()
  }
  match validate_g1_point(r_b_point, "r_b_point") {
    Err(msg) => return Err(msg)
    Ok(_) => ()
  }
  let r_b_u256 = r_b.to_u256()
  let g1 = pair_g2_g1(de_b, r_a_point)
  let g2 = pair_g2_g1(@ec.G2Affine::generator(), p_pub_e).cyclotomic_pow_u256(
    r_b_u256,
  )
  let g3 = g1.cyclotomic_pow_u256(r_b_u256)
  let ra_raw = r_a_point.to_bytes_raw()
  let rb_raw = r_b_point.to_bytes_raw()
  let g1_bytes = g1.to_bytes()
  let g2_bytes = g2.to_bytes()
  let g3_bytes = g3.to_bytes()
  let kdf_input = concat_bytes([
    id_a, id_b, ra_raw, rb_raw, g1_bytes, g2_bytes, g3_bytes,
  ])
  let sk = @sm3.kdf(kdf_input, klen)
  if is_all_zero(sk) {
    return Err("derived shared key SK_B is all zero")
  }
  let inner = compute_inner_hash(g2_bytes, g3_bytes, id_a, id_b, ra_raw, rb_raw)
  let s_b = compute_confirm_hash(b'\x82', g1_bytes, inner)
  let s_2 = compute_confirm_hash(b'\x83', g1_bytes, inner)
  Ok({ sk, s_b, s_2, })
}

///|
/// Executes the SM9 key exchange initiator steps (User A, GB/T 38635.3-2020 §6.2 Steps A5-A8).
///
/// Computes:
/// - `g1 = e(P2, p_pub_e)^{r_a}`
/// - `g2 = e(de_a, r_b_point)`
/// - `g3 = g2^{r_a}`
/// - `S_1 = SM3(0x82 || g1 || SM3(g2 || g3 || id_a || id_b || R_A_raw || R_B_raw))`
/// - If `peer_s_b` is provided, verifies `S_1 == peer_s_b` in constant time and returns
///   `Err("key confirmation S_B mismatch")` immediately on mismatch.
/// - `SK_A = KDF(id_a || id_b || R_A_raw || R_B_raw || g1 || g2 || g3, klen)`
/// - `S_A = SM3(0x83 || g1 || SM3(g2 || g3 || id_a || id_b || R_A_raw || R_B_raw))`
pub fn initiator_exchange(
  p_pub_e : @ec.G1Affine,
  id_a : BytesView,
  id_b : BytesView,
  de_a : @ec.G2Affine,
  r_a : @field.Fn,
  r_a_point : @ec.G1Affine,
  r_b_point : @ec.G1Affine,
  klen : Int32,
  peer_s_b? : BytesView,
) -> Result[InitiatorResult, String] {
  if klen <= 0 || klen > MAX_KDF_LEN {
    return Err("klen must be in [1, MAX_KDF_LEN]")
  }
  if r_a.is_zero() {
    return Err("ephemeral scalar r_a must be non-zero")
  }
  match validate_g1_point(p_pub_e, "p_pub_e") {
    Err(msg) => return Err(msg)
    Ok(_) => ()
  }
  match validate_g2_point(de_a, "de_a") {
    Err(msg) => return Err(msg)
    Ok(_) => ()
  }
  match validate_g1_point(r_a_point, "r_a_point") {
    Err(msg) => return Err(msg)
    Ok(_) => ()
  }
  match validate_g1_point(r_b_point, "r_b_point") {
    Err(msg) => return Err(msg)
    Ok(_) => ()
  }
  let r_a_u256 = r_a.to_u256()
  let g1 = pair_g2_g1(@ec.G2Affine::generator(), p_pub_e).cyclotomic_pow_u256(
    r_a_u256,
  )
  let g2 = pair_g2_g1(de_a, r_b_point)
  let g3 = g2.cyclotomic_pow_u256(r_a_u256)
  let ra_raw = r_a_point.to_bytes_raw()
  let rb_raw = r_b_point.to_bytes_raw()
  let g1_bytes = g1.to_bytes()
  let g2_bytes = g2.to_bytes()
  let g3_bytes = g3.to_bytes()
  let inner = compute_inner_hash(g2_bytes, g3_bytes, id_a, id_b, ra_raw, rb_raw)
  let s_1 = compute_confirm_hash(b'\x82', g1_bytes, inner)
  match peer_s_b {
    Some(sb) =>
      if !@sm3.ct_eq_bytes(s_1, sb) {
        return Err("key confirmation S_B mismatch")
      }
    None => ()
  }
  let kdf_input = concat_bytes([
    id_a, id_b, ra_raw, rb_raw, g1_bytes, g2_bytes, g3_bytes,
  ])
  let sk = @sm3.kdf(kdf_input, klen)
  if is_all_zero(sk) {
    return Err("derived shared key SK_A is all zero")
  }
  let s_a = compute_confirm_hash(b'\x83', g1_bytes, inner)
  Ok({ sk, s_a, s_1, })
}

///|
/// Constant-time verification on the responder side (User B, GB/T 38635.3-2020 §6.2 Step B9)
/// checking that `received_sa` matches the expected 32-byte confirmation tag `expected_s2`.
pub fn verify_responder_confirmation(
  expected_s2 : BytesView,
  received_sa : BytesView,
) -> Bool {
  if expected_s2.length() != 32 || received_sa.length() != 32 {
    return false
  }
  @sm3.ct_eq_bytes(expected_s2, received_sa)
}
