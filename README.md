# Cloudflare ProxyIP Scanner

自动扫描可用的 Cloudflare ProxyIP 并更新 DNS 记录。

## 工作原理

1. 每 12 小时自动扫描 Cloudflare IP 段
2. 测试每个 IP 是否可用作 ProxyIP（CONNECT + TLS）
3. 按延迟排序，选取最优 IP
4. 自动更新到你的域名 DNS 记录（灰色云朵，不走 CF 代理）

## 配置

GitHub Secrets 需要设置：

| Secret | 说明 |
|--------|------|
| `CF_API_TOKEN` | Cloudflare 全局 API Key |
| `CF_ZONE_ID` | Zone ID |
| `CF_DOMAIN` | 域名（如 zhaobo.org）|
| `CF_RECORD_NAME` | DNS 记录名（如 proxyip）|

## 使用

edgetunnel 的 `PROXYIP` 环境变量填：`proxyip.zhaobo.org`

## 手动触发

在 GitHub Actions 页面点击 "Run workflow"。
