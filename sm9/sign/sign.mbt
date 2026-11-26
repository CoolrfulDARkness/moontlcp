///|
/// SM9 digital signature `(h, S)` (GB/T 38635.2-2020).
/// Private fields enforce the invariants `h in [1, N - 1]` and `S in G1 \ {O}`.
#derive(Debug)
pub struct Signature {
  priv h : @field.Fn
  priv s : @ec.G1Affine
}

///|
/// Constant-time equality comparison on `Signature`.
pub fn Signature::ct_eq(self : Signature, other : Signature) -> Bool {
  let h_eq = @field.ct_mask(self.h.ct_eq(other.h))
  let s_eq = @field.ct_mask(self.s.ct_eq(other.s))
  (h_eq & s_eq) != 0UL
}

///|
pub impl Eq for Signature with fn equal(self, other) {
  self.ct_eq(other)
}

///|
/// Constructs a validated `Signature` after checking `h in [1, N - 1]` and `S in G1 \ {O}`.
pub fn Signature::new_checked(h : @field.Fn, s : @ec.G1Affine) -> Signature? {
  if h.is_zero() || s.is_infinity() || !s.is_on_curve() {
    return None
  }
  Some({ h, s, })
}

///|
/// Returns the signature hash scalar `h in [1, N - 1]`.
pub fn Signature::h(self : Signature) -> @field.Fn {
  self.h
}

///|
/// Returns the signature curve point `S in G1 \ {O}`.
pub fn Signature::s(self : Signature) -> @ec.G1Affine {
  self.s
}

///|
/// Raw 96-byte encoding `h (32B) || x_S (32B) || y_S (32B)` (GB/T 38635.2).
pub fn Signature::to_bytes_raw(self : Signature) -> Bytes {
  let hb = self.h.to_be_bytes()
  let sb = self.s.to_bytes_raw()
  Bytes::makei(96, fn(i) { if i < 32 { hb[i] } else { sb[i - 32] } })
}

///|
/// Strictly decodes 96 raw bytes `h (32B) || x_S (32B) || y_S (32B)` into a `Signature`.
/// Rejects wrong length, `h == 0`, `h >= N`, off-curve `S`, or infinity `S`.
pub fn Signature::from_bytes_raw_strict(b : BytesView) -> Signature? {
  if b.length() != 96 {
    return None
  }
  match
    (
      @field.Fn::from_be_bytes_nonzero(b[0:32]),
      @ec.G1Affine::from_bytes_raw_strict(b[32:96]),
    ) {
    (Some(h), Some(s)) => Signature::new_checked(h, s)
    _ => None
  }
}

///|
/// Uncompressed 97-byte encoding `h (32B) || 0x04 || x_S (32B) || y_S (32B)` (GM/T 0080).
pub fn Signature::to_bytes_uncompressed(self : Signature) -> Bytes {
  let hb = self.h.to_be_bytes()
  let sb = self.s.to_bytes_uncompressed()
  Bytes::makei(97, fn(i) { if i < 32 { hb[i] } else { sb[i - 32] } })
}

///|
/// Strictly decodes 97 uncompressed bytes `h (32B) || 0x04 || x_S (32B) || y_S (32B)`.
/// Rejects wrong length, non-`0x04` prefix, `h == 0`, `h >= N`, off-curve `S`, or infinity `S`.
pub fn Signature::from_bytes_uncompressed_strict(b : BytesView) -> Signature? {
  if b.length() != 97 {
    return None
  }
  match
    (
      @field.Fn::from_be_bytes_nonzero(b[0:32]),
      @ec.G1Affine::from_bytes_uncompressed_strict(b[32:97]),
    ) {
    (Some(h), Some(s)) => Signature::new_checked(h, s)
    _ => None
  }
}

///|
/// Computes `H1(id || hid, N) in [1, N - 1]` (GB/T 38635.1 §5.4.2.2).
fn h1_id(id : BytesView, hid : Byte) -> @field.Fn {
  let id_len = id.length()
  let z = Bytes::makei(id_len + 1, fn(i) {
    if i < id_len {
      id[i]
    } else {
      hid
    }
  })
  let h_bytes = @sm3.h1(z, @field.order_n.to_be_bytes())
  match @field.Fn::from_be_bytes_nonzero(h_bytes) {
    Some(v) => v
    None => abort("sign: H1 output unexpectedly outside [1, N - 1]")
  }
}

///|
/// Computes `H2(msg || FE2OS(w), N) in [1, N - 1]` (GB/T 38635.1 §5.4.2.3 & GB/T 38635.2).
fn h2_msg_w(msg : BytesView, w : @field.Fp12) -> @field.Fn {
  let w_bytes = w.to_bytes()
  let msg_len = msg.length()
  let z = Bytes::makei(msg_len + w_bytes.length(), fn(i) {
    if i < msg_len {
      msg[i]
    } else {
      w_bytes[i - msg_len]
    }
  })
  let h_bytes = @sm3.h2(z, @field.order_n.to_be_bytes())
  match @field.Fn::from_be_bytes_nonzero(h_bytes) {
    Some(v) => v
    None => abort("sign: H2 output unexpectedly outside [1, N - 1]")
  }
}

///|
fn update_be_u64(hasher : @sm3.Sm3, v : UInt64) -> Unit {
  hasher.update_byte((v >> 56).to_byte())
  hasher.update_byte((v >> 48).to_byte())
  hasher.update_byte((v >> 40).to_byte())
  hasher.update_byte((v >> 32).to_byte())
  hasher.update_byte((v >> 24).to_byte())
  hasher.update_byte((v >> 16).to_byte())
  hasher.update_byte((v >> 8).to_byte())
  hasher.update_byte(v.to_byte())
}

///|
fn update_be_u32(hasher : @sm3.Sm3, v : UInt32) -> Unit {
  hasher.update_byte((v >> 24).to_byte())
  hasher.update_byte((v >> 16).to_byte())
  hasher.update_byte((v >> 8).to_byte())
  hasher.update_byte(v.to_byte())
}

///|
/// Derives a deterministic non-zero nonce `r in [1, N - 1]` via domain-separated SM3
/// over `p_pub_s || ds || len(msg) || msg || len(entropy) || entropy || ctr`, followed
/// by 40-byte expansion modulo `(N - 1)` plus `1` (bias `< 2^-64`).
fn derive_deterministic_r(
  p_pub_raw : Bytes,
  ds_raw : Bytes,
  msg : BytesView,
  entropy : BytesView,
  ctr : UInt32,
) -> @field.Fn {
  let hasher = @sm3.Sm3::new()
  hasher.update(b"SM9-SIGN-DETERMINISTIC-NONCE-V1\x00")
  hasher.update(p_pub_raw)
  hasher.update(ds_raw)
  update_be_u64(hasher, msg.length().to_uint64())
  hasher.update(msg)
  update_be_u64(hasher, entropy.length().to_uint64())
  hasher.update(entropy)
  update_be_u32(hasher, ctr)
  let seed = hasher.finalize()
  let r_bytes = @sm3.h2(seed, @field.order_n.to_be_bytes())
  match @field.Fn::from_be_bytes_nonzero(r_bytes) {
    Some(r) => r
    None => abort("sign: deterministic nonce unexpectedly outside [1, N - 1]")
  }
}

///|
/// Validates that a precomputed pairing element `g` is a non-trivial member of the
/// cyclotomic subgroup `G_{Phi_6}(Fp2)` (`g != 0`, `g != 1`, `g^{p^6 + 1} == 1`, and
/// `g^{p^4 - p^2 + 1} == 1`), rejecting `-1` and arbitrary non-cyclotomic `Fp12` elements.
fn is_valid_precomputed_g(g : @field.Fp12) -> Bool {
  if g.is_zero() || g.is_one() {
    return false
  }
  if !g.conjugate().mul(g).is_one() {
    return false
  }
  let fp2 = g.frobenius_p2()
  fp2.frobenius_p2().mul(g).ct_eq(fp2)
}

///|
/// Precomputes the pairing element `g = e(P_pub-s, P1) in GT` (GB/T 38635.2 §6.2 A1 / §7.2 B3).
/// Reusing `g` across signatures and verifications eliminates one full pairing per operation.
pub fn precompute_g(p_pub_s : @ec.G2Affine) -> @field.Fp12 {
  if p_pub_s.is_infinity() {
    return @field.Fp12::one()
  }
  let p1 = @ec.G1Affine::generator()
  @pairing.pair_coords(p_pub_s.x(), p_pub_s.y(), p1.x(), p1.y())
}

///|
/// Signs `msg` using a precomputed `g = e(P_pub-s, P1)`, signing private key `ds in G1 \ {O}`,
/// and caller-supplied non-zero nonce `r in [1, N - 1]` (GB/T 38635.2 §6.2).
pub fn sign_with_r_precomputed(
  g : @field.Fp12,
  ds : @ec.G1Affine,
  msg : BytesView,
  r : @field.Fn,
) -> Result[Signature, String] {
  if !is_valid_precomputed_g(g) {
    return Err("invalid precomputed pairing g")
  }
  if ds.is_infinity() || !ds.is_on_curve() {
    return Err("invalid signing private key ds")
  }
  if r.is_zero() {
    return Err("nonce r must be non-zero")
  }
  // A3: w = g^r in GT (cyclotomic subgroup exponentiation)
  let w = g.cyclotomic_pow_u256(r.to_u256())
  // A4: h = H2(M || w, N)
  let h = h2_msg_w(msg, w)
  // A5: l = (r - h) mod N; reject if l == 0
  let l = r.sub(h)
  if l.is_zero() {
    return Err("nonce collision: l == 0")
  }
  // A6: S = [l]ds_A
  let s = ds.scalar_mul_fn(l).to_affine()
  if s.is_infinity() {
    return Err("invalid signature point: S is infinity")
  }
  Ok({ h, s, })
}

///|
/// Signs `msg` with master signing public key `p_pub_s in G2 \ {O}`, user signing private key
/// `ds in G1 \ {O}`, and caller-supplied non-zero nonce `r in [1, N - 1]` (GB/T 38635.2 §6.2).
pub fn sign_with_r(
  p_pub_s : @ec.G2Affine,
  ds : @ec.G1Affine,
  msg : BytesView,
  r : @field.Fn,
) -> Result[Signature, String] {
  if p_pub_s.is_infinity() ||
    !p_pub_s.is_on_curve() ||
    !p_pub_s.is_in_subgroup() {
    return Err("invalid master public key p_pub_s")
  }
  if ds.is_infinity() || !ds.is_on_curve() {
    return Err("invalid signing private key ds")
  }
  if r.is_zero() {
    return Err("nonce r must be non-zero")
  }
  let g = precompute_g(p_pub_s)
  sign_with_r_precomputed(g, ds, msg, r)
}

///|
/// Deterministically signs `msg` without external randomness by deriving `r in [1, N - 1]`
/// from `p_pub_s`, `ds`, `msg`, `entropy`, and a retry counter `ctr` using domain-separated SM3.
/// Automatically increments `ctr` if the negligible `l == 0` collision occurs.
pub fn sign_deterministic(
  p_pub_s : @ec.G2Affine,
  ds : @ec.G1Affine,
  msg : BytesView,
  entropy : BytesView,
) -> Result[Signature, String] {
  if p_pub_s.is_infinity() ||
    !p_pub_s.is_on_curve() ||
    !p_pub_s.is_in_subgroup() {
    return Err("invalid master public key p_pub_s")
  }
  if ds.is_infinity() || !ds.is_on_curve() {
    return Err("invalid signing private key ds")
  }
  let g = precompute_g(p_pub_s)
  let p_pub_raw = p_pub_s.to_bytes_raw()
  let ds_raw = ds.to_bytes_raw()
  for ctr = 0U; ctr < 256U; ctr = ctr + 1U {
    let r = derive_deterministic_r(p_pub_raw, ds_raw, msg, entropy, ctr)
    match sign_with_r_precomputed(g, ds, msg, r) {
      Ok(sig) => return Ok(sig)
      Err(err) =>
        if err == "nonce collision: l == 0" {
          continue
        } else {
          return Err(err)
        }
    }
  }
  Err("deterministic nonce derivation exhausted retries")
}

///|
/// Internal signature verification assuming `p_pub_s` has already passed full
/// G2 curve and prime-order subgroup validation.
fn verify_unchecked_pub(
  p_pub_s : @ec.G2Affine,
  g : @field.Fp12,
  id : BytesView,
  msg : BytesView,
  sig : Signature,
  hid~ : Byte = b'\x01',
) -> Bool {
  if !is_valid_precomputed_g(g) {
    return false
  }
  // B1-B2: check h in [1, N - 1] and S in G1 \ {O}
  if sig.h.is_zero() || sig.s.is_infinity() || !sig.s.is_on_curve() {
    return false
  }
  // B4: t = g^h
  let t = g.cyclotomic_pow_u256(sig.h.to_u256())
  // B5: h1 = H1(ID_A || hid, N)
  let h1 = h1_id(id, hid)
  // B6: P = [h1]P2 + P_pub-s
  let p = @ec.G2Affine::generator()
    .scalar_mul_fn(h1)
    .add_mixed(p_pub_s)
    .to_affine()
  if p.is_infinity() {
    return false
  }
  // B7: u = e(P, S)
  let u = @pairing.pair_coords(p.x(), p.y(), sig.s.x(), sig.s.y())
  // B8: w' = u * t, h2 = H2(M || w', N), check h2 == h in constant time
  let w_prime = u.mul(t)
  let h2 = h2_msg_w(msg, w_prime)
  h2.ct_eq(sig.h)
}

///|
/// Verifies an SM9 signature `(h, S)` against `id` and `msg` using a precomputed
/// `g = e(P_pub-s, P1)` (GB/T 38635.2 §7.2).
pub fn verify_precomputed(
  p_pub_s : @ec.G2Affine,
  g : @field.Fp12,
  id : BytesView,
  msg : BytesView,
  sig : Signature,
  hid~ : Byte = b'\x01',
) -> Bool {
  if p_pub_s.is_infinity() ||
    !p_pub_s.is_on_curve() ||
    !p_pub_s.is_in_subgroup() {
    return false
  }
  verify_unchecked_pub(p_pub_s, g, id, msg, sig, hid~)
}

///|
/// Verifies an SM9 signature `(h, S)` against master public key `p_pub_s`, signer identity `id`,
/// and message `msg` (GB/T 38635.2 §7.2). Default `hid` is `0x01`.
pub fn verify(
  p_pub_s : @ec.G2Affine,
  id : BytesView,
  msg : BytesView,
  sig : Signature,
  hid~ : Byte = b'\x01',
) -> Bool {
  if p_pub_s.is_infinity() ||
    !p_pub_s.is_on_curve() ||
    !p_pub_s.is_in_subgroup() {
    return false
  }
  let g = precompute_g(p_pub_s)
  verify_unchecked_pub(p_pub_s, g, id, msg, sig, hid~)
}
