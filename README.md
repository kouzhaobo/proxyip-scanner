# ProxyIP Resolver

从多个社区 ProxyIP 域名聚合可用 IP，自动测试可用性并更新到指定的 Cloudflare DNS。

## 功能特性

- ✅ **证书与风控校验** — 自动校验 TLS 证书，检测 Cloudflare 人机验证及 1034 错误
- ✅ **官方 CIDR 过滤** — 自动剔除 Cloudflare 官方 CDN 节点，确保提取的均为真实 VPS 反代
- ✅ **IPv6 / IPv4 双栈** — 支持分别配置 IPv4 与 IPv6 候选数量
- ✅ **多轮复验** — 3 轮并发测试，淘汰抖动与不稳定 IP
- ✅ **地区优先排序** — 结合 GeoIP 对亚太及欧美优先地区进行智能排序
- ✅ **自动更新 DNS** — 自动同步更新 Cloudflare DNS 的 A / AAAA 记录

## 工作原理

```
社区 ProxyIP 域名列表
    ↓ DNS 解析提取全部 VPS IP (排除私有网段与 CF 官方段)
    ↓ 并行可用性测试 + 人机风控检测 + 多轮复验
    ↓ 按地区优先级与平均延迟排序
    写入自定义域名的 A/AAAA 记录 (灰色云朵 / DNS-only)
```

## 使用

在代理项目（如 edgetunnel）的 `PROXYIP` 环境变量中填写你配置的自定义解析域名（例如 `proxyip.yourdomain.com`）。

## 配置说明

在 GitHub 仓库的 **Settings -> Secrets and variables -> Actions** 中配置以下 Secrets：

| Secret | 说明 |
|--------|------|
| `CF_API_TOKEN` | Cloudflare Global API Key 或具备 DNS 编辑权限的 Token |
| `CF_ZONE_ID` | 目标域名的 Zone ID |
| `CF_DOMAIN` | 根域名（例如 `example.com`） |
| `CF_RECORD_NAME` | 子域名记录名前缀（例如 `proxyip`） |
| `CF_EMAIL` | Cloudflare 账户邮箱（使用 Global API Key 时必需） |

## 环境变量说明

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `CERT_VERIFY_MODE` | `strict` | 证书验证模式（`strict` / `none`） |
| `ENABLE_IPV6` | `false` | 是否启用 IPv6 扫描 |
| `MAX_LATENCY` | `500` | 最大允许延迟（ms） |
| `MAX_RESULTS_V4` | `30` | IPv4 保留数量 |
| `MAX_RESULTS_V6` | `30` | IPv6 保留数量 |
| `VERIFY_ROUNDS` | `3` | 复验轮数 |
| `SCAN_THREADS` | `100` | 并发测试线程数 |

## 调度机制

通过 GitHub Actions 每小时定时自动运行，也支持在 Actions 页面手动触发执行。
