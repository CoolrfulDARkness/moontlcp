import assert from "node:assert/strict";
import * as api from "../../_build/js/release/build/web_api/web_api.js";

console.log("=== MoonTLCP web_api ESM Smoke Test (Node " + process.version + ") ===");

// 1. All 4 GM/T 0024 cipher suites normal handshakes + UTF-8 Chinese payload
const suites = [
  "ECC_SM4_CBC_SM3",
  "ECC_SM4_GCM_SM3",
  "ECDHE_SM4_CBC_SM3",
  "ECDHE_SM4_GCM_SM3",
];
for (const suite of suites) {
  const payload = `国密 TLCP 1.1 测试 — ${suite} "ok"`;
  const res = JSON.parse(api.run_tlcp_handshake(suite, false, "none", payload));
  assert.equal(res.ok, true, `${suite} normal handshake should pass`);
  assert.equal(res.suite, suite);
  assert.equal(res.app_plaintext_recovered, payload);
  assert.equal(res.alert_or_error, "");
  assert.ok(res.flights.length >= 5, `${suite} should record >=5 flights`);
  assert.ok(res.total_wire_bytes > 500, `${suite} should transfer >500B`);
  console.log(
    `  [PASS] TLCP ${suite} (mutual=${res.mutual_auth}) | flights=${res.flights.length} | wire=${res.total_wire_bytes}B`
  );
}

// 2. ECC mutual auth (mTLCP)
{
  const res = JSON.parse(
    api.run_tlcp_handshake("ECC_SM4_GCM_SM3", true, "none", "mTLCP-ECC-payload")
  );
  assert.equal(res.ok, true);
  assert.equal(res.mutual_auth, true);
  assert.equal(res.app_plaintext_recovered, "mTLCP-ECC-payload");
  console.log(`  [PASS] TLCP ECC_SM4_GCM_SM3 mTLCP | wire=${res.total_wire_bytes}B`);
}

// 3. Red-team tamper modes
{
  const ctGcm = JSON.parse(
    api.run_tlcp_handshake("ECC_SM4_GCM_SM3", false, "tamper_ciphertext", "secret")
  );
  assert.equal(ctGcm.ok, false);
  assert.match(ctGcm.alert_or_error, /BadRecordMac/);
  assert.equal(ctGcm.app_plaintext_recovered, "");
  console.log(`  [PASS] Red-Team tamper_ciphertext (GCM) blocked: ${ctGcm.alert_or_error}`);

  const ctCbc = JSON.parse(
    api.run_tlcp_handshake("ECC_SM4_CBC_SM3", false, "tamper_ciphertext", "secret")
  );
  assert.equal(ctCbc.ok, false);
  assert.match(ctCbc.alert_or_error, /BadRecordMac/);
  console.log(`  [PASS] Red-Team tamper_ciphertext (CBC) blocked: ${ctCbc.alert_or_error}`);

  const swap = JSON.parse(
    api.run_tlcp_handshake("ECC_SM4_GCM_SM3", false, "swap_dual_certs", "secret")
  );
  assert.equal(swap.ok, false);
  assert.match(swap.alert_or_error, /CertificateError/);
  assert.match(swap.alert_or_error, /swapped dual certs/);
  assert.ok(
    swap.flights.some((f) => f.label.includes("BadCertificate")),
    "client should emit Fatal Alert(BadCertificate) on swapped dual certs"
  );
  console.log(`  [PASS] Red-Team swap_dual_certs blocked: ${swap.alert_or_error}`);

  const fin = JSON.parse(
    api.run_tlcp_handshake("ECDHE_SM4_GCM_SM3", true, "tamper_finished", "secret")
  );
  assert.equal(fin.ok, false);
  assert.match(fin.alert_or_error, /BadRecordMac/);
  console.log(`  [PASS] Red-Team tamper_finished blocked: ${fin.alert_or_error}`);
}

// 4. Session ID abbreviated resumption benchmark
{
  const res = JSON.parse(api.run_tlcp_session_resume("ECC_SM4_GCM_SM3"));
  assert.equal(res.ok, true);
  assert.equal(res.resumed_ok, true);
  assert.ok(res.full_wire_bytes > res.resumed_wire_bytes);
  assert.ok(res.savings_percent >= 70, `expected >=70% savings, got ${res.savings_percent}%`);
  assert.equal(res.session_id_hex.length, 64);
  console.log(
    `  [PASS] Session Resume (${res.suite}) | ${res.full_wire_bytes}B -> ${res.resumed_wire_bytes}B (-${res.savings_percent}%)`
  );
}

// 5. SM9 BN256 IBC (KDF-XOR, SM4-ECB-PKCS#7, and 1-bit signature tamper)
for (const mode of ["kdf_xor", "sm4_ecb"]) {
  const msg = `SM9 邮箱即公钥测试 (${mode})`;
  const res = JSON.parse(
    api.run_sm9_demo("alice@gm.cn", "bob@gm.cn", msg, mode, false)
  );
  assert.equal(res.ok, true, `SM9 ${mode} should pass`);
  assert.equal(res.sig_valid, true);
  assert.equal(res.tamper_blocked, false);
  assert.equal(res.decrypted_message, msg);
  assert.equal(res.keyex_confirmed, true);
  assert.equal(res.shared_key_hex.length, 64);
  assert.equal(res.sig_h_hex.length, 64);
  console.log(
    `  [PASS] SM9 ${mode} | sig_valid=true | keyex_confirmed=true | ct=${res.ciphertext_hex.length / 2}B`
  );
}
{
  const res = JSON.parse(
    api.run_sm9_demo("alice@gm.cn", "bob@gm.cn", "tamper test", "sm4_ecb", true)
  );
  assert.equal(res.ok, false);
  assert.equal(res.sig_valid, false);
  assert.equal(res.tamper_blocked, true);
  assert.equal(res.keyex_confirmed, true);
  console.log(`  [PASS] SM9 1-bit signature tamper blocked: sig_valid=false, tamper_blocked=true`);
}

console.log("=== ALL web_api ESM SMOKE CHECKS PASSED ===");
