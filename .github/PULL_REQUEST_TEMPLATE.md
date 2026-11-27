## 变更摘要与关联 Issue
Closes #

## 必跑验证门禁（请贴实测结果）
- [ ] `moon fmt --check` 通过
- [ ] `moon info` 已执行，`.mbti` 变更已逐行核验（无非预期破坏或 `priv` 泄露）
- [ ] `moon check -d` 全仓 0 warnings, 0 errors
- [ ] `moon test --target wasm -d` / `--target js -d` / `--target native -d` 全绿
- [ ] `python harness/interop_openssl.py` 8/8 PASS，且无脏 diff 残留
- [ ] `moon build web_api --target js --release && node examples/web-demo/smoke.mjs && node examples/tlcp-tcp-demo/tlcp_tcp_demo.mjs` 全绿

## AI 辅助使用与可解释性声明
- 是否使用 AI 辅助：是 / 否
- 本人独立设计、核验并可完整解释的关键技术决策与安全边界：
  1.
  2.
