# Contributing to MoonTLCP

感谢你参与 `CoolrfulDARkness/moontlcp`（国密 TLCP 1.1 + SM9 全栈）的持续建设！为保障密码学安全红线与零回退接续开发，请遵循以下规范：

## 1. 新会话 / 新贡献者 3 分钟冷启动必读顺序
1. `AGENTS.md`（块风格 `///|` 与工具链命令）
2. `moon.mod` 与各包 `pkg.generated.mbti`（冻结的公开 ABI 契约）
3. `docs/ARCHITECTURE.md`（分层 DAG 与 Threat Model / Non-Goals）
4. `docs/SECURITY_AUDIT.md`（历史 P0/P1 安全禁区，严禁回退）
5. `docs/ROADMAP.md` 与 GitHub Open Issues

## 2. 不可妥协的架构与安全红线
- 核心协议与密码学包（`crypto/*`、`x509/*`、`record`、`handshake`、`state`、`sm9/*`）必须永久保持 **纯 MoonBit、零外部依赖、零 FFI、零 `unsafe`、Sans-I/O**；
- `sm9/*` 必须持续复用 `crypto/sm3`、`crypto/sm4`、`crypto/ct`，严禁引入重复 SM3/SM4 实现；
- 严禁放宽双证书 `KeyUsage` 角色分离、CA 证书冒充叶证书拦截、防 Lucky13 恒定时间 CBC-HMAC-SM3、RFC 5288 严格 `seq_num` GCM Nonce 或 64 KiB 握手重组上限；
- 任何异步网络 I/O（如 `moonbitlang/async`）或浏览器 Demo 必须隔离在 `examples/` 或独立适配子包中。

## 3. 提交 PR 前必跑门禁（全部 0 警告通过）
```bash
moon fmt --check
moon info && git diff --exit-code -- '*.mbti'   # 若有意新增导出请在 PR 中逐行说明
moon check -d
moon test --target wasm -d
moon test --target js -d
moon test --target native -d
python harness/interop_openssl.py
moon build web_api --target js --release && node examples/web-demo/smoke.mjs && node examples/tlcp-tcp-demo/tlcp_tcp_demo.mjs
```
