# ProxyIP Resolver

从多个社区 ProxyIP 域名聚合可用 IP，自动更新到你的域名 DNS。

## 工作原理

```
25+ 个社区 ProxyIP 域名（分地区）
    ↓ DoH 解析获取 IP
    所有 IP 去重 (上百个)
    ↓ 并行测试可用性
    可用 IP 按延迟排序
    ↓ 取前 30 个
    写入 proxyip.zhaobo.org 的 A 记录 (灰色云朵)
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

## 调度

每 12 小时自动运行（GitHub Actions），也可手动触发。
