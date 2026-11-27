///|
/// Comprehensive unit tests for `CoolrfulDARkness/moontlcp/web_api` covering:
/// - All 4 GM/T 0024 cipher suites (normal handshake + UTF-8 Chinese/JSON payload)
/// - All 3 red-team tamper modes (`tamper_ciphertext`, `swap_dual_certs`, `tamper_finished`)
/// - Session ID abbreviated resumption bandwidth savings
/// - GB/T 38635 SM9 (`kdf_xor` & `sm4_ecb`, clean & 1-bit tampered signature)
/// - Stateful OS TCP bridge handles full handshake + bidirectional encrypted app data

///|
fn str_contains(haystack : String, needle : String) -> Bool {
  if needle.length() == 0 {
    return true
  }
  if needle.length() > haystack.length() {
    return false
  }
  let limit = haystack.length() - needle.length()
  for i = 0; i <= limit; i = i + 1 {
    let mut matched = true
    for j = 0; j < needle.length(); j = j + 1 {
      if haystack[i + j] != needle[j] {
        matched = false
        break
      }
    }
    if matched {
      return true
    }
  }
  false
}

///|
fn parse_positive_int(s : String) -> Int32 {
  let mut acc = 0
  for i = 0; i < s.length(); i = i + 1 {
    let d = s[i].to_int() - 48
    acc = acc * 10 + d
  }
  acc
}

///|
fn split_pipe_two(s : String) -> (String, String) {
  let left = StringBuilder()
  let right = StringBuilder()
  let mut seen = false
  for i = 0; i < s.length(); i = i + 1 {
    let ch = s[i].to_int().unsafe_to_char()
    if !seen && ch == '|' {
      seen = true
    } else if !seen {
      left.write_char(ch)
    } else {
      right.write_char(ch)
    }
  }
  (left.to_string(), right.to_string())
}

///|
fn strip_prefix(s : String, prefix : String) -> String {
  let buf = StringBuilder()
  for i = prefix.length(); i < s.length(); i = i + 1 {
    buf.write_char(s[i].to_int().unsafe_to_char())
  }
  buf.to_string()
}

///|
test "web_api: TLCP handshake succeeds for all 4 GM/T 0024 suites with UTF-8 payload" {
  let suites = [
    "ECC_SM4_CBC_SM3", "ECC_SM4_GCM_SM3", "ECDHE_SM4_CBC_SM3", "ECDHE_SM4_GCM_SM3",
  ]
  for i = 0; i < suites.length(); i = i + 1 {
    let suite = suites[i]
    let msg = "国密TLCP1.1测试-\"quote\"\\" + suite
    let res = @web_api.run_tlcp_handshake(suite, false, "none", msg)
    assert_true(str_contains(res, "\"ok\":true"))
    assert_true(str_contains(res, "\"suite\":\"" + suite + "\""))
    assert_true(str_contains(res, "\"alert_or_error\":\"\""))
    assert_true(
      str_contains(res, "国密TLCP1.1测试-\\\"quote\\\"\\\\" + suite),
    )
    assert_true(str_contains(res, "\"flights\":["))
    assert_true(str_contains(res, "digitalSignature"))
    assert_true(str_contains(res, "keyEncipherment"))
  }
}

///|
test "web_api: TLCP ECC mutual auth (mTLCP) succeeds" {
  let res = @web_api.run_tlcp_handshake(
    "ECC_SM4_GCM_SM3", true, "none", "mTLCP mutual auth payload",
  )
  assert_true(str_contains(res, "\"ok\":true"))
  assert_true(str_contains(res, "\"mutual_auth\":true"))
  assert_true(str_contains(res, "CertificateRequest"))
  assert_true(str_contains(res, "CertificateVerify"))
  assert_true(
    str_contains(
      res, "\"app_plaintext_recovered\":\"mTLCP mutual auth payload\"",
    ),
  )
}

///|
test "web_api: TLCP red-team tamper modes all fail closed with expected alerts" {
  let r_ct = @web_api.run_tlcp_handshake(
    "ECC_SM4_GCM_SM3", false, "tamper_ciphertext", "secret wire transfer",
  )
  assert_true(str_contains(r_ct, "\"ok\":false"))
  assert_true(str_contains(r_ct, "BadRecordMac"))
  assert_true(str_contains(r_ct, "\"app_plaintext_recovered\":\"\""))

  let r_ct_cbc = @web_api.run_tlcp_handshake(
    "ECC_SM4_CBC_SM3", false, "tamper_ciphertext", "cbc padding oracle test",
  )
  assert_true(str_contains(r_ct_cbc, "\"ok\":false"))
  assert_true(str_contains(r_ct_cbc, "BadRecordMac"))

  let r_swap = @web_api.run_tlcp_handshake(
    "ECC_SM4_GCM_SM3", false, "swap_dual_certs", "should not reach app",
  )
  assert_true(str_contains(r_swap, "\"ok\":false"))
  assert_true(str_contains(r_swap, "BadCertificate"))
  assert_true(str_contains(r_swap, "swapped dual certs"))

  let r_fin = @web_api.run_tlcp_handshake(
    "ECDHE_SM4_GCM_SM3", true, "tamper_finished", "should not establish",
  )
  assert_true(str_contains(r_fin, "\"ok\":false"))
  assert_true(str_contains(r_fin, "BadRecordMac"))
}

///|
test "web_api: TLCP Session ID resumption succeeds with significant bandwidth savings" {
  let res = @web_api.run_tlcp_session_resume("ECC_SM4_GCM_SM3")
  assert_true(str_contains(res, "\"ok\":true"))
  assert_true(str_contains(res, "\"resumed_ok\":true"))
  assert_true(str_contains(res, "\"savings_percent\":7"))
  assert_true(!str_contains(res, "\"session_id_hex\":\"\""))

  let res_ecdhe = @web_api.run_tlcp_session_resume("ECDHE_SM4_CBC_SM3")
  assert_true(str_contains(res_ecdhe, "\"ok\":true"))
  assert_true(str_contains(res_ecdhe, "\"resumed_ok\":true"))
}

///|
test "web_api: SM9 IBC workbench passes KDF-XOR, SM4-ECB, and blocks 1-bit tampered signature" {
  let r_xor = @web_api.run_sm9_demo(
    "alice@gm.cn", "bob@gm.cn", "SM9 标识密码 KDF-XOR 测试", "kdf_xor", false,
  )
  assert_true(str_contains(r_xor, "\"ok\":true"))
  assert_true(str_contains(r_xor, "\"enc_mode\":\"kdf_xor\""))
  assert_true(str_contains(r_xor, "\"sig_valid\":true"))
  assert_true(str_contains(r_xor, "\"tamper_blocked\":false"))
  assert_true(str_contains(r_xor, "\"keyex_confirmed\":true"))
  assert_true(
    str_contains(
      r_xor, "\"decrypted_message\":\"SM9 标识密码 KDF-XOR 测试\"",
    ),
  )

  let r_sm4 = @web_api.run_sm9_demo(
    "alice@bank.cn", "bob@bank.cn", "SM9 SM4-ECB-PKCS7 payload", "sm4_ecb", false,
  )
  assert_true(str_contains(r_sm4, "\"ok\":true"))
  assert_true(str_contains(r_sm4, "\"enc_mode\":\"sm4_ecb\""))
  assert_true(str_contains(r_sm4, "\"sig_valid\":true"))
  assert_true(str_contains(r_sm4, "\"keyex_confirmed\":true"))
  assert_true(
    str_contains(r_sm4, "\"decrypted_message\":\"SM9 SM4-ECB-PKCS7 payload\""),
  )

  let r_tamper = @web_api.run_sm9_demo(
    "alice@bank.cn", "bob@bank.cn", "Tamper check", "sm4_ecb", true,
  )
  assert_true(str_contains(r_tamper, "\"ok\":false"))
  assert_true(str_contains(r_tamper, "\"sig_valid\":false"))
  assert_true(str_contains(r_tamper, "\"tamper_blocked\":true"))
  assert_true(str_contains(r_tamper, "\"keyex_confirmed\":true"))
}

///|
test "web_api: stateful TCP bridge handles complete TLCP handshake and bidirectional app data" {
  let init = @web_api.tlcp_tcp_init_pair("ECDHE_SM4_CBC_SM3", true)
  assert_true(str_contains(init, "OK:"))
  let (c_str, s_str) = split_pipe_two(strip_prefix(init, "OK:"))
  let cid = parse_positive_int(c_str)
  let sid = parse_positive_int(s_str)

  // Drive handshake via poll_out / feed_in
  let mut c_est = false
  let mut s_est = false
  for _round = 0; _round < 8; _round = _round + 1 {
    let c_out = @web_api.tlcp_tcp_poll_out(cid)
    assert_true(str_contains(c_out, "OK:"))
    let c_hex = strip_prefix(c_out, "OK:")
    if c_hex.length() > 0 {
      let s_in = @web_api.tlcp_tcp_feed_in(sid, c_hex)
      assert_true(str_contains(s_in, "OK:"))
      if str_contains(s_in, "ESTABLISHED") {
        s_est = true
      }
    }
    let s_out = @web_api.tlcp_tcp_poll_out(sid)
    assert_true(str_contains(s_out, "OK:"))
    let s_hex = strip_prefix(s_out, "OK:")
    if s_hex.length() > 0 {
      let c_in = @web_api.tlcp_tcp_feed_in(cid, s_hex)
      assert_true(str_contains(c_in, "OK:"))
      if str_contains(c_in, "ESTABLISHED") {
        c_est = true
      }
    }
    if c_est && s_est {
      break
    }
  }
  assert_true(c_est)
  assert_true(s_est)

  // Client -> Server encrypted app message
  assert_eq(@web_api.tlcp_tcp_send_app(cid, "PING-TLCP-TCP"), "OK")
  let req_wire = strip_prefix(@web_api.tlcp_tcp_poll_out(cid), "OK:")
  assert_true(req_wire.length() > 0)
  let s_recv = @web_api.tlcp_tcp_feed_in(sid, req_wire)
  // "PING-TLCP-TCP" in ASCII hex = 50494e472d544c43502d544350
  assert_eq(s_recv, "OK:ESTABLISHED|50494e472d544c43502d544350")

  // Server -> Client encrypted app message
  assert_eq(@web_api.tlcp_tcp_send_app(sid, "PONG-OK"), "OK")
  let resp_wire = strip_prefix(@web_api.tlcp_tcp_poll_out(sid), "OK:")
  assert_true(resp_wire.length() > 0)
  let c_recv = @web_api.tlcp_tcp_feed_in(cid, resp_wire)
  // "PONG-OK" in ASCII hex = 504f4e472d4f4b
  assert_eq(c_recv, "OK:ESTABLISHED|504f4e472d4f4b")

  // Clean close & verify closed handle rejected
  assert_eq(@web_api.tlcp_tcp_close(cid), "OK")
  assert_eq(@web_api.tlcp_tcp_close(sid), "OK")
  assert_true(str_contains(@web_api.tlcp_tcp_poll_out(cid), "ERR:"))
}
