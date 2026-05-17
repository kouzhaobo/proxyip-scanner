# ProxyIP Resolver

从多个社区 ProxyIP 域名聚合可用 IP，自动更新到你的域名 DNS。

## 功能特性

- ✅ **证书验证** — 验证 SSL 证书有效性，修复"此网站不安全"问题
- ✅ **IPv6 支持** — 同时扫描 IPv4 和 IPv6 地址
- ✅ **测速功能** — 测试下载速度，过滤低速 IP
- ✅ **多轮复验** — 3 轮测试，淘汰不稳定 IP
- ✅ **地区优先** — 8 个优先地区智能排序
- ✅ **自动更新** — 自动更新 Cloudflare DNS

## 工作原理

```
25+ 个社区 ProxyIP 域名（分地区）
    ↓ DoH 解析获取 IPv4/IPv6 IP
    所有 IP 去重 (上百个)
    ↓ 并行测试可用性 + 测速
    可用 IP 按延迟/速度排序
    ↓ IPv4 取 20 个，IPv6 取 30 个
    写入 proxyip.zhaobo.org 的 A/AAAA 记录 (灰色云朵)
```

## 上游域名（25+ 个）

**CMLiussss 分地区：**
HK / SG / JP / KR / IN / GB / FR / DE / NL / SE / FI / PL / RU / CH / LV / US / CA

**其他社区：**
- `kr.william.us.ci` / `tw.william.us.ci`
- `proxy.xinyitang.dpdns.org`
- `cdn.xn--b6gac.eu.org` / `cdn-all.edtunnel.ml`

## 使用

edgetunnel 的 `PROXYIP` 环境变量填：`proxyip.zhaobo.org`

## 配置

GitHub Secrets：

| Secret | 说明 |
|--------|------|
| `CF_API_TOKEN` | Cloudflare 全局 API Key |
| `CF_ZONE_ID` | Zone ID |
| `CF_DOMAIN` | 域名 |
| `CF_RECORD_NAME` | DNS 记录名 |
| `CF_EMAIL` | CF 账户邮箱 |

## 环境变量

| 变量名 | 默认值 | 说明 |
|--------|--------|------|
| `CERT_VERIFY_MODE` | `strict` | 证书验证模式（strict/none） |
| `ENABLE_IPV6` | `true` | 启用 IPv6 支持 |
| `ENABLE_SPEED_TEST` | `true` | 启用测速功能 |
| `SPEED_TEST_URL` | `https://speed.cloudflare.com/__down?bytes=10485760` | 测速文件 URL |
| `SPEED_TEST_TIMEOUT` | `30` | 测速超时（秒） |
| `MIN_DOWNLOAD_SPEED` | `10` | 最低下载速度（Mbps） |
| `MAX_LATENCY` | `300` | 最大延迟（ms） |
| `MAX_RESULTS_V4` | `20` | IPv4 保留数量 |
| `MAX_RESULTS_V6` | `30` | IPv6 保留数量 |
| `VERIFY_ROUNDS` | `3` | 复验轮数 |
| `TEST_DOMAINS` | CF 官方站点 | 自定义测试域名（逗号分隔） |

## 调度

每 12 小时自动运行（GitHub Actions），也可手动触发。

## 输出示例

```
[*] 最终 50 个 IP (IPv4: 20, IPv6: 30):
    ★ 49.238.236.28 - JP Tokyo - avg 33ms jitter 5ms speed 150.5Mbps
    ★ 150.136.254.79 - US San Jose - avg 117ms jitter 12ms speed 85.2Mbps
    ★ 2606:4700::1 (IPv6) - US San Francisco - avg 45ms jitter 8ms speed 120.3Mbps
    ...
```
