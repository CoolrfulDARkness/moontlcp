///|
/// Private key generation function identifier for SM9 digital signatures (GB/T 38635.2).
pub const HID_SIGN : Byte = b'\x01'

///|
/// Private key generation function identifier for SM9 key exchange (GB/T 38635.3).
pub const HID_KEYEX : Byte = b'\x02'

///|
/// Private key generation function identifier for SM9 KEM and public-key encryption (GB/T 38635.4).
pub const HID_ENC : Byte = b'\x03'

///|
/// Domain separator for deterministic derivation of SM9 signing master private keys.
let sign_master_seed_domain : Bytes = b"SM9-KGC-SIGN-MASTER-KEY-V1"

///|
/// Domain separator for deterministic derivation of SM9 encryption/key-exchange master private keys.
let enc_master_seed_domain : Bytes = b"SM9-KGC-ENC-MASTER-KEY-V1"

///|
/// Big-endian 32-byte encoding of BN256 subgroup order `N`.
fn order_n_be_bytes() -> Bytes {
  @field.order_n.to_be_bytes()
}

///|
/// Concatenates two byte slices into a single owned `Bytes`.
fn concat_views(a : BytesView, b : BytesView) -> Bytes {
  let alen = a.length()
  let blen = b.length()
  Bytes::makei(alen + blen, fn(i) { if i < alen { a[i] } else { b[i - alen] } })
}

///|
/// Appends a single byte to a byte slice.
fn concat_view_byte(a : BytesView, b : Byte) -> Bytes {
  let alen = a.length()
  Bytes::makei(alen + 1, fn(i) { if i < alen { a[i] } else { b } })
}

///|
/// Deterministically derives a valid non-zero master scalar in `[1, N - 1]` using SM3 `H1`
/// with explicit domain separation.
fn derive_master_scalar(domain : Bytes, seed : BytesView) -> @field.Fn {
  let input = concat_views(domain, seed)
  let h_bytes = @sm3.h1(input, order_n_be_bytes())
  match @field.Fn::from_be_bytes_nonzero(h_bytes) {
    Some(s) => s
    None => abort("kgc: H1 returned out-of-range scalar")
  }
}

///|
/// Computes the SM9 identity hash scalar `H1(id || hid, N)` in `[1, N - 1]`
/// (GB/T 38635.1-2020 §5.4.2.2).
pub fn h1_scalar(id : BytesView, hid : Byte) -> @field.Fn {
  let z = concat_view_byte(id, hid)
  let h_bytes = @sm3.h1(z, order_n_be_bytes())
  match @field.Fn::from_be_bytes_nonzero(h_bytes) {
    Some(s) => s
    None => abort("kgc: H1 returned out-of-range scalar")
  }
}

///|
/// Computes the R-ate bilinear pairing `e(Q, P)` for `Q in G2` and `P in G1`.
/// Returns `Fp12::one()` if either point is the point at infinity.
pub fn pair(q : @ec.G2Affine, p : @ec.G1Affine) -> @field.Fp12 {
  if q.is_infinity() || p.is_infinity() {
    @field.Fp12::one()
  } else {
    @pairing.pair_coords(q.x(), q.y(), p.x(), p.y())
  }
}

///|
/// KGC signing master private key `ks in [1, N - 1]` (GB/T 38635.2).
pub struct SignMasterPrivateKey {
  priv ks : @field.Fn
}

///|
/// Strictly parses a 32-byte big-endian signing master private key `ks`,
/// enforcing `1 <= ks < N`.
pub fn SignMasterPrivateKey::from_bytes_strict(
  b : BytesView,
) -> SignMasterPrivateKey? {
  match @field.Fn::from_be_bytes_nonzero(b) {
    Some(ks) => Some({ ks, })
    None => None
  }
}

///|
/// Wraps a non-zero scalar `ks in [1, N - 1]` as a signing master private key.
pub fn SignMasterPrivateKey::from_fn(ks : @field.Fn) -> SignMasterPrivateKey? {
  if ks.is_zero() {
    None
  } else {
    Some({ ks, })
  }
}

///|
/// Deterministically derives a valid signing master private key `ks in [1, N - 1]`
/// from `seed` using domain-separated SM3.
pub fn SignMasterPrivateKey::from_seed(
  seed : BytesView,
) -> SignMasterPrivateKey {
  { ks: derive_master_scalar(sign_master_seed_domain, seed), }
}

///|
/// Returns the underlying scalar `ks`.
pub fn SignMasterPrivateKey::scalar(self : SignMasterPrivateKey) -> @field.Fn {
  self.ks
}

///|
/// Computes the corresponding signing master public key `P_pub-s = [ks]P2`.
pub fn SignMasterPrivateKey::public_key(
  self : SignMasterPrivateKey,
) -> SignMasterPublicKey {
  let p_pub_s = @ec.G2Affine::generator().scalar_mul_fn(self.ks).to_affine()
  { p_pub_s, }
}

///|
/// Serializes `ks` as a 32-byte big-endian byte string.
pub fn SignMasterPrivateKey::to_bytes(self : SignMasterPrivateKey) -> Bytes {
  self.ks.to_be_bytes()
}

///|
/// Constant-time equality for signing master private keys.
pub fn SignMasterPrivateKey::ct_eq(
  self : SignMasterPrivateKey,
  other : SignMasterPrivateKey,
) -> Bool {
  self.ks.ct_eq(other.ks)
}

///|
pub impl Eq for SignMasterPrivateKey with fn equal(self, other) {
  self.ct_eq(other)
}

///|
/// KGC signing master public key `P_pub-s in G2` (GB/T 38635.2).
pub struct SignMasterPublicKey {
  priv p_pub_s : @ec.G2Affine
}

///|
/// Validates and wraps a finite on-curve `G2` subgroup point as `SignMasterPublicKey`.
pub fn SignMasterPublicKey::from_g2(pt : @ec.G2Affine) -> SignMasterPublicKey? {
  if pt.is_infinity() || !pt.is_on_curve() || !pt.is_in_subgroup() {
    None
  } else {
    Some({ p_pub_s: pt, })
  }
}

///|
/// Returns the underlying `G2Affine` point `P_pub-s`.
pub fn SignMasterPublicKey::to_g2(self : SignMasterPublicKey) -> @ec.G2Affine {
  self.p_pub_s
}

///|
/// Strictly decodes 128 raw bytes `x1 || x0 || y1 || y0` into `SignMasterPublicKey`.
pub fn SignMasterPublicKey::from_bytes_raw_strict(
  b : BytesView,
) -> SignMasterPublicKey? {
  match @ec.G2Affine::from_bytes_raw_strict(b) {
    Some(p_pub_s) => Some({ p_pub_s, })
    None => None
  }
}

///|
/// Strictly decodes 129 uncompressed bytes `0x04 || x1 || x0 || y1 || y0` into `SignMasterPublicKey`.
pub fn SignMasterPublicKey::from_bytes_uncompressed_strict(
  b : BytesView,
) -> SignMasterPublicKey? {
  match @ec.G2Affine::from_bytes_uncompressed_strict(b) {
    Some(p_pub_s) => Some({ p_pub_s, })
    None => None
  }
}

///|
/// Encodes `P_pub-s` as 128 raw bytes `x1 || x0 || y1 || y0`.
pub fn SignMasterPublicKey::to_bytes_raw(self : SignMasterPublicKey) -> Bytes {
  self.p_pub_s.to_bytes_raw()
}

///|
/// Encodes `P_pub-s` as 129 uncompressed bytes `0x04 || x1 || x0 || y1 || y0`.
pub fn SignMasterPublicKey::to_bytes_uncompressed(
  self : SignMasterPublicKey,
) -> Bytes {
  self.p_pub_s.to_bytes_uncompressed()
}

///|
/// Precomputes the signing pairing base `g = e(P_pub-s, P1)`.
pub fn SignMasterPublicKey::precompute_g(
  self : SignMasterPublicKey,
) -> @field.Fp12 {
  pair(self.p_pub_s, @ec.G1Affine::generator())
}

///|
/// Constant-time equality for signing master public keys.
pub fn SignMasterPublicKey::ct_eq(
  self : SignMasterPublicKey,
  other : SignMasterPublicKey,
) -> Bool {
  self.p_pub_s.ct_eq(other.p_pub_s)
}

///|
pub impl Eq for SignMasterPublicKey with fn equal(self, other) {
  self.ct_eq(other)
}

///|
/// User signing private key `ds in G1` (GB/T 38635.2).
pub struct SignUserPrivateKey {
  priv ds : @ec.G1Affine
}

///|
/// Validates and wraps a finite on-curve `G1` point as `SignUserPrivateKey`.
pub fn SignUserPrivateKey::from_g1(pt : @ec.G1Affine) -> SignUserPrivateKey? {
  if pt.is_infinity() || !pt.is_on_curve() {
    None
  } else {
    Some({ ds: pt, })
  }
}

///|
/// Returns the underlying `G1Affine` point `ds`.
pub fn SignUserPrivateKey::to_g1(self : SignUserPrivateKey) -> @ec.G1Affine {
  self.ds
}

///|
/// Strictly decodes 64 raw bytes `x || y` into `SignUserPrivateKey`.
pub fn SignUserPrivateKey::from_bytes_raw_strict(
  b : BytesView,
) -> SignUserPrivateKey? {
  match @ec.G1Affine::from_bytes_raw_strict(b) {
    Some(ds) => Some({ ds, })
    None => None
  }
}

///|
/// Strictly decodes 65 uncompressed bytes `0x04 || x || y` into `SignUserPrivateKey`.
pub fn SignUserPrivateKey::from_bytes_uncompressed_strict(
  b : BytesView,
) -> SignUserPrivateKey? {
  match @ec.G1Affine::from_bytes_uncompressed_strict(b) {
    Some(ds) => Some({ ds, })
    None => None
  }
}

///|
/// Encodes `ds` as 64 raw bytes `x || y`.
pub fn SignUserPrivateKey::to_bytes_raw(self : SignUserPrivateKey) -> Bytes {
  self.ds.to_bytes_raw()
}

///|
/// Encodes `ds` as 65 uncompressed bytes `0x04 || x || y`.
pub fn SignUserPrivateKey::to_bytes_uncompressed(
  self : SignUserPrivateKey,
) -> Bytes {
  self.ds.to_bytes_uncompressed()
}

///|
/// Constant-time equality for user signing private keys.
pub fn SignUserPrivateKey::ct_eq(
  self : SignUserPrivateKey,
  other : SignUserPrivateKey,
) -> Bool {
  self.ds.ct_eq(other.ds)
}

///|
pub impl Eq for SignUserPrivateKey with fn equal(self, other) {
  self.ct_eq(other)
}

///|
/// KGC encryption / key-exchange master private key `ke in [1, N - 1]` (GB/T 38635.3 / .4).
pub struct EncMasterPrivateKey {
  priv ke : @field.Fn
}

///|
/// Strictly parses a 32-byte big-endian encryption master private key `ke`,
/// enforcing `1 <= ke < N`.
pub fn EncMasterPrivateKey::from_bytes_strict(
  b : BytesView,
) -> EncMasterPrivateKey? {
  match @field.Fn::from_be_bytes_nonzero(b) {
    Some(ke) => Some({ ke, })
    None => None
  }
}

///|
/// Wraps a non-zero scalar `ke in [1, N - 1]` as an encryption master private key.
pub fn EncMasterPrivateKey::from_fn(ke : @field.Fn) -> EncMasterPrivateKey? {
  if ke.is_zero() {
    None
  } else {
    Some({ ke, })
  }
}

///|
/// Deterministically derives a valid encryption / key-exchange master private key `ke in [1, N - 1]`
/// from `seed` using domain-separated SM3.
pub fn EncMasterPrivateKey::from_seed(seed : BytesView) -> EncMasterPrivateKey {
  { ke: derive_master_scalar(enc_master_seed_domain, seed), }
}

///|
/// Returns the underlying scalar `ke`.
pub fn EncMasterPrivateKey::scalar(self : EncMasterPrivateKey) -> @field.Fn {
  self.ke
}

///|
/// Computes the corresponding encryption master public key `P_pub-e = [ke]P1`.
pub fn EncMasterPrivateKey::public_key(
  self : EncMasterPrivateKey,
) -> EncMasterPublicKey {
  let p_pub_e = @ec.G1Affine::generator().scalar_mul_fn(self.ke).to_affine()
  { p_pub_e, }
}

///|
/// Serializes `ke` as a 32-byte big-endian byte string.
pub fn EncMasterPrivateKey::to_bytes(self : EncMasterPrivateKey) -> Bytes {
  self.ke.to_be_bytes()
}

///|
/// Constant-time equality for encryption master private keys.
pub fn EncMasterPrivateKey::ct_eq(
  self : EncMasterPrivateKey,
  other : EncMasterPrivateKey,
) -> Bool {
  self.ke.ct_eq(other.ke)
}

///|
pub impl Eq for EncMasterPrivateKey with fn equal(self, other) {
  self.ct_eq(other)
}

///|
/// KGC encryption / key-exchange master public key `P_pub-e in G1` (GB/T 38635.3 / .4).
pub struct EncMasterPublicKey {
  priv p_pub_e : @ec.G1Affine
}

///|
/// Validates and wraps a finite on-curve `G1` point as `EncMasterPublicKey`.
pub fn EncMasterPublicKey::from_g1(pt : @ec.G1Affine) -> EncMasterPublicKey? {
  if pt.is_infinity() || !pt.is_on_curve() {
    None
  } else {
    Some({ p_pub_e: pt, })
  }
}

///|
/// Returns the underlying `G1Affine` point `P_pub-e`.
pub fn EncMasterPublicKey::to_g1(self : EncMasterPublicKey) -> @ec.G1Affine {
  self.p_pub_e
}

///|
/// Strictly decodes 64 raw bytes `x || y` into `EncMasterPublicKey`.
pub fn EncMasterPublicKey::from_bytes_raw_strict(
  b : BytesView,
) -> EncMasterPublicKey? {
  match @ec.G1Affine::from_bytes_raw_strict(b) {
    Some(p_pub_e) => Some({ p_pub_e, })
    None => None
  }
}

///|
/// Strictly decodes 65 uncompressed bytes `0x04 || x || y` into `EncMasterPublicKey`.
pub fn EncMasterPublicKey::from_bytes_uncompressed_strict(
  b : BytesView,
) -> EncMasterPublicKey? {
  match @ec.G1Affine::from_bytes_uncompressed_strict(b) {
    Some(p_pub_e) => Some({ p_pub_e, })
    None => None
  }
}

///|
/// Encodes `P_pub-e` as 64 raw bytes `x || y`.
pub fn EncMasterPublicKey::to_bytes_raw(self : EncMasterPublicKey) -> Bytes {
  self.p_pub_e.to_bytes_raw()
}

///|
/// Encodes `P_pub-e` as 65 uncompressed bytes `0x04 || x || y`.
pub fn EncMasterPublicKey::to_bytes_uncompressed(
  self : EncMasterPublicKey,
) -> Bytes {
  self.p_pub_e.to_bytes_uncompressed()
}

///|
/// Precomputes the encryption / key-exchange pairing base `g = e(P2, P_pub-e)`.
pub fn EncMasterPublicKey::precompute_g(
  self : EncMasterPublicKey,
) -> @field.Fp12 {
  pair(@ec.G2Affine::generator(), self.p_pub_e)
}

///|
/// Constant-time equality for encryption master public keys.
pub fn EncMasterPublicKey::ct_eq(
  self : EncMasterPublicKey,
  other : EncMasterPublicKey,
) -> Bool {
  self.p_pub_e.ct_eq(other.p_pub_e)
}

///|
pub impl Eq for EncMasterPublicKey with fn equal(self, other) {
  self.ct_eq(other)
}

///|
/// User encryption / key-exchange private key `de in G2` (GB/T 38635.3 / .4).
pub struct EncUserPrivateKey {
  priv de : @ec.G2Affine
}

///|
/// Validates and wraps a finite on-curve `G2` subgroup point as `EncUserPrivateKey`.
pub fn EncUserPrivateKey::from_g2(pt : @ec.G2Affine) -> EncUserPrivateKey? {
  if pt.is_infinity() || !pt.is_on_curve() || !pt.is_in_subgroup() {
    None
  } else {
    Some({ de: pt, })
  }
}

///|
/// Returns the underlying `G2Affine` point `de`.
pub fn EncUserPrivateKey::to_g2(self : EncUserPrivateKey) -> @ec.G2Affine {
  self.de
}

///|
/// Strictly decodes 128 raw bytes `x1 || x0 || y1 || y0` into `EncUserPrivateKey`.
pub fn EncUserPrivateKey::from_bytes_raw_strict(
  b : BytesView,
) -> EncUserPrivateKey? {
  match @ec.G2Affine::from_bytes_raw_strict(b) {
    Some(de) => Some({ de, })
    None => None
  }
}

///|
/// Strictly decodes 129 uncompressed bytes `0x04 || x1 || x0 || y1 || y0` into `EncUserPrivateKey`.
pub fn EncUserPrivateKey::from_bytes_uncompressed_strict(
  b : BytesView,
) -> EncUserPrivateKey? {
  match @ec.G2Affine::from_bytes_uncompressed_strict(b) {
    Some(de) => Some({ de, })
    None => None
  }
}

///|
/// Encodes `de` as 128 raw bytes `x1 || x0 || y1 || y0`.
pub fn EncUserPrivateKey::to_bytes_raw(self : EncUserPrivateKey) -> Bytes {
  self.de.to_bytes_raw()
}

///|
/// Encodes `de` as 129 uncompressed bytes `0x04 || x1 || x0 || y1 || y0`.
pub fn EncUserPrivateKey::to_bytes_uncompressed(
  self : EncUserPrivateKey,
) -> Bytes {
  self.de.to_bytes_uncompressed()
}

///|
/// Constant-time equality for user encryption / key-exchange private keys.
pub fn EncUserPrivateKey::ct_eq(
  self : EncUserPrivateKey,
  other : EncUserPrivateKey,
) -> Bool {
  self.de.ct_eq(other.de)
}

///|
pub impl Eq for EncUserPrivateKey with fn equal(self, other) {
  self.ct_eq(other)
}

///|
/// Extracts a user signing private key `ds = [ks * (H1(id || hid, N) + ks)^-1 mod N]P1`
/// (GB/T 38635.2-2020 §6.1).
/// Returns `Err` if `t1 = (H1(id || hid, N) + ks) mod N == 0`, in which case the KGC
/// must regenerate the signing master key pair.
pub fn extract_sign_private_key(
  master : SignMasterPrivateKey,
  id : BytesView,
  hid~ : Byte = HID_SIGN,
) -> Result[SignUserPrivateKey, String] {
  let h1 = h1_scalar(id, hid)
  let t1 = h1.add(master.ks)
  match t1.inv() {
    None => Err("t1 == 0: KGC must regenerate signing master private key")
    Some(t1_inv) => {
      let t2 = master.ks.mul(t1_inv)
      let ds = @ec.G1Affine::generator().scalar_mul_fn(t2).to_affine()
      if ds.is_infinity() {
        Err("derived signing user private key is point at infinity")
      } else {
        Ok({ ds, })
      }
    }
  }
}

///|
/// Shared extraction routine for `de = [ke * (H1(id || hid, N) + ke)^-1 mod N]P2`
/// used by both SM9 key exchange (`hid = 0x02`) and encryption (`hid = 0x03`).
fn extract_enc_user_key(
  master : EncMasterPrivateKey,
  id : BytesView,
  hid : Byte,
) -> Result[EncUserPrivateKey, String] {
  let h1 = h1_scalar(id, hid)
  let t1 = h1.add(master.ke)
  match t1.inv() {
    None => Err("t1 == 0: KGC must regenerate encryption master private key")
    Some(t1_inv) => {
      let t2 = master.ke.mul(t1_inv)
      let de = @ec.G2Affine::generator().scalar_mul_fn(t2).to_affine()
      if de.is_infinity() {
        Err("derived encryption user private key is point at infinity")
      } else {
        Ok({ de, })
      }
    }
  }
}

///|
/// Extracts a user key-exchange private key `de in G2` (GB/T 38635.3-2020 §6.1, default `hid = 0x02`).
pub fn extract_keyex_private_key(
  master : EncMasterPrivateKey,
  id : BytesView,
  hid~ : Byte = HID_KEYEX,
) -> Result[EncUserPrivateKey, String] {
  extract_enc_user_key(master, id, hid)
}

///|
/// Extracts a user encryption / KEM private key `de in G2` (GB/T 38635.4-2020 §6.1, default `hid = 0x03`).
pub fn extract_enc_private_key(
  master : EncMasterPrivateKey,
  id : BytesView,
  hid~ : Byte = HID_ENC,
) -> Result[EncUserPrivateKey, String] {
  extract_enc_user_key(master, id, hid)
}

///|
/// Derives the encryption / key-exchange user public point `Q_id = [H1(id || hid, N)]P1 + P_pub-e` in `G1`
/// (GB/T 38635.3 / .4).
pub fn derive_enc_user_public_point(
  p_pub_e : EncMasterPublicKey,
  id : BytesView,
  hid : Byte,
) -> @ec.G1Affine {
  let h1 = h1_scalar(id, hid)
  @ec.G1Affine::generator()
  .scalar_mul_fn(h1)
  .add_mixed(p_pub_e.p_pub_e)
  .to_affine()
}

///|
/// Derives the signing user public point `P = [H1(id || hid, N)]P2 + P_pub-s` in `G2`
/// (GB/T 38635.2, default `hid = 0x01`).
pub fn derive_sign_user_public_point(
  p_pub_s : SignMasterPublicKey,
  id : BytesView,
  hid~ : Byte = HID_SIGN,
) -> @ec.G2Affine {
  let h1 = h1_scalar(id, hid)
  @ec.G2Affine::generator()
  .scalar_mul_fn(h1)
  .add_mixed(p_pub_s.p_pub_s)
  .to_affine()
}
