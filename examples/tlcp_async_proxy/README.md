# tlcp_async_proxy — Native MoonBit Concurrent Async TLCP 1.1 Reverse Proxy

Standalone native MoonBit module demonstrating a real OS TCP (`127.0.0.1`) concurrent GM/T 0024-2023 (TLCP 1.1) reverse proxy, plaintext HTTP/1.1 backend, and async TLCP client built on [`moonbitlang/async/socket`](https://mooncakes.io/docs/moonbitlang/async/socket) (`TcpServer` / `Tcp` + `@async.with_task_group`) and [`CoolrfulDARkness/moontlcp`](https://mooncakes.io/docs/CoolrfulDARkness/moontlcp).

> Core `CoolrfulDARkness/moontlcp` remains **100% zero-dependency** across Wasm / JS / Native; async socket I/O lives exclusively in this standalone example module.

## Capabilities Demonstrated

- **PEM Dual-Certificate Verification**: Serializes and reloads SM2 `[sign, enc]` PEM chains (`parse_certs_pem` + `verify_dual_certs`) and blocks swapped `[enc, sign]` bundles at startup.
- **Structured Concurrency (`@async.with_task_group` + `@async.Semaphore`)**: Accepts concurrent TCP clients on `127.0.0.1`, terminates TLCP 1.1, injects `X-TLCP-Suite` / `X-TLCP-Resumed` / `X-TLCP-Client-CN` audit headers, forwards plaintext HTTP/1.1 requests over OS TCP to an upstream backend, encrypts the response back, and performs graceful `close_notify` + structured task-group shutdown.
- **Session ID Resumption (`SessionStore`)**: Concurrent `ECC_SM4_GCM_SM3` full handshakes followed by concurrent abbreviated Session ID resumptions over real OS loopback TCP.
- **mTLCP Mutual Authentication**: Concurrent `ECDHE_SM4_CBC_SM3` and `ECDHE_SM4_GCM_SM3` (>32 KiB multi-record auto-fragmentation) mutual-auth connections, rejecting unauthenticated peers.
- **Fail-Closed Active Attack Defense**: Live SM4-GCM authentication tag bit-flip triggers `BadRecordMac` Fatal Alert and disconnect; raw TLS 1.2 (`0x0303`) downgrade probe triggers `ProtocolVersion` Fatal Alert; zero tampered requests reach the plaintext backend.

## Run Tests & Live CLI Demo (Native Target)

Linux / macOS:
```bash
cd examples/tlcp_async_proxy
moon update
moon test --target native -d
moon run --target native cmd/main
```

Windows (MSVC Build Tools x64):
```powershell
cd examples\tlcp_async_proxy
moon update
cmd /c '"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul && moon test --target native -d && moon run --target native cmd/main'
```
