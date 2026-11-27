# MoonTLCP 开发路线图（Roadmap）

本路线图仅规划面向未来的演进里程碑（`v0.4.0 → v1.0.0+`），所有已交付能力（含 `v0.3.0` 原生并发异步国密反向代理 `examples/tlcp_async_proxy/`、无状态线格式解剖 API、TLCP 1.1 全套件与 SM9 BN256）请参见 [`README.md`](../README.md) 与 [`docs/VERIFICATION_LOG.md`](VERIFICATION_LOG.md)。

## `v0.4.0`：热点加速、Tongsuo 生产互操作与形式化边界验证
- [ ] 对 `crypto/sm4`、`crypto/sm3` 与 `sm9/pairing` 开展跨后端热点剖析，评估 Wasm `v128` SIMD / Native 向量化加速路径，并保留标量参考实现及逐位一致性回归测试；
- [ ] 推进独立代理模块与 Tongsuo / BabaSSL 的长连接高并发双向互操作压测及背压稳定性验证；
- [ ] 发布对标 OpenSSL / GmSSL 的吞吐与 `.wasm` KB 级产物尺寸对比报告；
- [ ] 为 Strict ASN.1 DER 长度解码、Record 16KB 分片重组与无状态解剖边界补充属性测试（PBT）及 `moon prove` 边界验证。

## `v0.5.0 → v1.0.0`：MoonBit 1.0 稳定版与公开 ABI 冻结
- [ ] 完整适配 MoonBit `1.0.0-rc` / `1.0` 稳定版编译器，严格维持核心协议包（`CoolrfulDARkness/moontlcp`）零外部依赖及 Wasm / JS / Native 三端 `-d` 零警告；
- [ ] 补齐独立安全审计复核与完整版本迁移指南（Migration Guide）；
- [ ] 冻结公开 `.mbti` ABI 契约并正式发布 `v1.0.0`。
