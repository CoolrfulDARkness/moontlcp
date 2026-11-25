///|
/// GM/T 0024-2023 §6.4.5.2 TLCP Dual-Certificate Bundle Parser and Chain Verifier.

///|
#derive(Debug, Eq)
pub struct DualCertBundle {
  sign_cert : Certificate
  enc_cert : Certificate
  intermediates : Array[Certificate]
}

///|
fn check_sign_cert_usage(cert : Certificate) -> Unit raise X509Error {
  match cert.key_usage {
    None => ()
    Some(ku) => {
      let has_sign = ku.digital_signature
      let has_enc = ku.key_encipherment ||
        ku.data_encipherment ||
        ku.key_agreement
      if !has_sign {
        if has_enc {
          raise DualCertMismatch(
            "signing certificate only permits encryption usage (possible swapped dual certs)",
          )
        }
        raise BadKeyUsage("signing certificate lacks digitalSignature")
      }
    }
  }
}

///|
fn check_enc_cert_usage(cert : Certificate) -> Unit raise X509Error {
  match cert.key_usage {
    None => ()
    Some(ku) => {
      let has_sign = ku.digital_signature
      let has_enc = ku.key_encipherment ||
        ku.data_encipherment ||
        ku.key_agreement
      if !has_enc {
        if has_sign {
          raise DualCertMismatch(
            "encryption certificate only permits signing usage (possible swapped dual certs)",
          )
        }
        raise BadKeyUsage(
          "encryption certificate lacks keyEncipherment/dataEncipherment/keyAgreement",
        )
      }
    }
  }
}

///|
fn verify_chain_dfs(
  current : Certificate,
  intermediates : Array[Certificate],
  trust_anchors : Array[Certificate],
  visited : Array[Bool],
  depth : Int32,
) -> X509Error? {
  // 1. Try direct verification against any trust anchor.
  let mut anchor_err : X509Error? = None
  for i = 0; i < trust_anchors.length(); i = i + 1 {
    let anchor = trust_anchors[i]
    try {
      current.verify_issued_by(anchor)
      return None
    } catch {
      e =>
        // Prefer preserving specific errors from a CN-matching trust anchor.
        if current.issuer_cn == anchor.subject_cn {
          anchor_err = Some(e)
        }
    }
  }
  if depth >= 8 {
    return Some(
      ChainVerificationFailed("certificate chain depth limit exceeded"),
    )
  }
  // 2. Try chaining through unused intermediates.
  for i = 0; i < intermediates.length(); i = i + 1 {
    if visited[i] {
      continue
    }
    let inter = intermediates[i]
    if inter.raw_der == current.raw_der {
      continue
    }
    let ok = try {
      current.verify_issued_by(inter)
      true
    } catch {
      _ => false
    }
    if ok {
      visited[i] = true
      let sub = verify_chain_dfs(
        inter,
        intermediates,
        trust_anchors,
        visited,
        depth + 1,
      )
      visited[i] = false
      match sub {
        None => return None
        Some(err) => if anchor_err is None { anchor_err = Some(err) }
      }
    }
  }
  match anchor_err {
    Some(e) => Some(e)
    None =>
      Some(
        ChainVerificationFailed(
          "no trusted issuer found for subject '" +
          current.subject_cn +
          "' (issuer '" +
          current.issuer_cn +
          "')",
        ),
      )
  }
}

///|
fn verify_cert_to_anchors(
  leaf : Certificate,
  intermediates : Array[Certificate],
  trust_anchors : Array[Certificate],
) -> Unit raise X509Error {
  if trust_anchors.is_empty() {
    raise ChainVerificationFailed("trust_anchors cannot be empty (fail-closed)")
  }
  let visited = Array::make(intermediates.length(), false)
  match verify_chain_dfs(leaf, intermediates, trust_anchors, visited, 0) {
    None => ()
    Some(err) => raise err
  }
}

///|
/// Parse and verify a GM/T 0024 §6.4.5.2 TLCP dual-certificate chain:
/// - `cert_ders[0]` = signing certificate (must allow `digitalSignature` if KeyUsage present)
/// - `cert_ders[1]` = encryption certificate (must allow `keyEncipherment`/`dataEncipherment`/`keyAgreement` if KeyUsage present)
/// - `cert_ders[2..]` = optional intermediate CA certificates
/// Both leaf certificates must verify to at least one CA in `trust_anchors` (fail-closed if empty).
pub fn parse_and_verify_dual_certs(
  cert_ders : Array[Bytes],
  trust_anchors : Array[Certificate],
) -> DualCertBundle raise X509Error {
  if cert_ders.length() < 2 {
    raise InvalidCertCount(cert_ders.length())
  }
  if trust_anchors.is_empty() {
    raise ChainVerificationFailed("trust_anchors cannot be empty (fail-closed)")
  }
  let sign_cert = Certificate::from_der(cert_ders[0])
  let enc_cert = Certificate::from_der(cert_ders[1])
  let intermediates : Array[Certificate] = []
  for i = 2; i < cert_ders.length(); i = i + 1 {
    intermediates.push(Certificate::from_der(cert_ders[i]))
  }
  if sign_cert.is_ca {
    raise BadKeyUsage(
      "signing certificate must be an end-entity leaf certificate (is_ca=true rejected)",
    )
  }
  if enc_cert.is_ca {
    raise BadKeyUsage(
      "encryption certificate must be an end-entity leaf certificate (is_ca=true rejected)",
    )
  }
  check_sign_cert_usage(sign_cert)
  check_enc_cert_usage(enc_cert)
  verify_cert_to_anchors(sign_cert, intermediates, trust_anchors)
  verify_cert_to_anchors(enc_cert, intermediates, trust_anchors)
  { sign_cert, enc_cert, intermediates, }
}
