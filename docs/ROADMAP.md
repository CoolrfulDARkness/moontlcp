# MoonTLCP 开发路线图（Roadmap）

本路线图面向后续接续开发者与新 AI 工程会话，精准对齐 2026 MoonBit 黑客松四维评审准则与长期开源可持续维护目标。

## 已完成基线：`v0.1.0`
- 统一零重复国密核心：`crypto/ct`、`crypto/sm3`、`crypto/sm4`、`crypto/sm2`（同时驱动 PKI TLCP 1.1 与 IBC SM9，静态扫描零重复 SM3/SM4 实现）；
- 完整 GM/T 0024-2014 / GB/T 38636-2020 TLCP 1.1 双证书协议栈 + GB/T 38635-2020 SM9 BN256 标识密码全栈；
- 三端 168/168 `-d` 零警告回归测试、23 项性能基准、OpenSSL 3.5.6 8/8 双向互操作、真实 OS TCP 回路演示、GitHub Pages 零安装浏览器交互工作台与双平台 CI。

## `v0.2.0`：外部消费端 CI 与下游只读解剖接口
- [ ] 新增独立 `examples/consumer` 工作区，通过 `moon add CoolrfulDARkness/moontlcp` 验证已发布 `mooncakes.io` 包零报错运行，接入双周定时 CI；
- [ ] 在 `record/` 与 `handshake/` 导出无状态只读解析 API（`inspect_record` / `inspect_handshake`），供下游抓包/解剖工具（如 `moonshark`）零耦合消费。

## `v0.3.0`：原生并发异步国密代理生产化
- [ ] 在独立 `examples/tlcp_async_proxy/` 中基于 `moonbitlang/async/socket` 交付多连接并发国密反向代理（支持 PEM 双证书链热加载与套件配置），实测与 Tongsuo / OpenSSL 长连接互操作；
- [ ] 严格保持核心协议包零外部依赖、三端全兼容。

## `v0.4.0 → v1.0.0`：MoonBit 1.0 稳定版、热点加速与 ABI 冻结
- [ ] 适配 MoonBit `1.0.0-rc1` / `1.0` 稳定版，三端 `-d` 零警告；
- [ ] 热点剖析 `crypto/sm4` 与 `crypto/sm3`（评估 `v128` SIMD 加速且保留标量参考实现与位级一致测试），发布对标 OpenSSL/GmSSL 的吞吐与 `.wasm` KB 级体积报告；
- [ ] 探索对 DER 长度解码与 Record 分片边界补充属性测试（PBT）及 `moon prove` 边界验证；
- [ ] 冻结公开 `.mbti` ABI 并发布 `v1.0.0`。
