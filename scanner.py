#!/usr/bin/env python3
"""
ProxyIP Resolver - 解析多个社区 ProxyIP 域名，聚合可用 IP 更新 DNS
带多轮复验、质量过滤、地区优先排序、证书验证、IPv6 支持、代理真实测速
"""

import socket
import ssl
import time
import json
import sys
import os
import re
import random
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# 社区 ProxyIP 域名列表
UPSTREAM_DOMAINS = [
    # CMLiussss 主域名
    "proxyip.cmliussss.net",
    # CMLiussss 分地区
    "proxyip.hk.cmliussss.net",
    "proxyip.sg.cmliussss.net",
    "proxyip.jp.cmliussss.net",
    "proxyip.kr.cmliussss.net",
    "proxyip.in.cmliussss.net",
    "proxyip.gb.cmliussss.net",
    "proxyip.fr.cmliussss.net",
    "proxyip.de.cmliussss.net",
    "proxyip.nl.cmliussss.net",
    "proxyip.se.cmliussss.net",
    "proxyip.fi.cmliussss.net",
    "proxyip.pl.cmliussss.net",
    "proxyip.ru.cmliussss.net",
    "proxyip.ch.cmliussss.net",
    "proxyip.lv.cmliussss.net",
    "proxyip.us.cmliussss.net",
    "proxyip.ca.cmliussss.net",
    # William
    "kr.william.us.ci",
    "tw.william.us.ci",
    # 新源堂
    "proxy.xinyitang.dpdns.org",
    # superhumanvssuperopen
    "proxy.superhumanvssuperopen.dpdns.org",
    # 备用
    "proxyip.hw.090227.xyz",
    "cdn.xn--b6gac.eu.org",
    "cdn-all.edtunnel.ml",
]

# IPv6 专用上游域名
UPSTREAM_DOMAINS_V6 = [
    # 新源堂 IPv6
    "sub.xinyitang.dpdns.org",
    # superhumanvssuperopen IPv6
    "proxyip-v6.superhumanvssuperopen.dpdns.org",
    "ipv6.superhumanvssuperopen.dpdns.org",
    "v6.superhumanvssuperopen.dpdns.org",
    # CMLiussss IPv6
    "ipv6.proxyip.cmliussss.net",
    "v6.proxyip.cmliussss.net",
    # Cloudflare Pages IPv6
    "ipv6.pages.dev",
    "v6.pages.dev",
    # 其他 IPv6
    "proxyip-v6.hw.090227.xyz",
    "ipv6.proxyip.hw.090227.xyz",
    "v6.proxyip.hw.090227.xyz",
]

# ── API 数据源（来自 Senflare-IP 等社区项目）──
API_SOURCES = [
    # 麒麟 (Kirin)
    "https://api.uouin.com/cloudflare.html",
    "https://api.urlce.com/cloudflare.html",
    # Hostmonit
    "https://addressesapi.090227.xyz/CloudFlareYes",
    "https://cf.090227.xyz/CloudFlareYes",
    # VPS789
    "https://vps789.com/openApi/cfIpTop20",
    "https://vps789.com/openApi/cfIpApi",
    # WeTest
    "https://www.wetest.vip/page/cloudflare/total_v4.html",
    # CMLiussss 分运营商
    "https://cf.090227.xyz/cmcc",   # 中国移动
    "https://cf.090227.xyz/ct",     # 中国电信
    # IPDB
    "https://ipdb.api.030101.xyz/?type=bestcf",
    "https://ipdb.api.030101.xyz/?type=bestproxy",
]

# 排除私有 / 保留网段 IP
PRIVATE_IP_REGEX = re.compile(
    r'^(?:127\.|10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.|0\.|169\.254\.)'
)

# 配置
TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", "5"))
DEFAULT_MAX_RES = int(os.environ.get("MAX_RESULTS", "30"))
MAX_RESULTS_V4 = int(os.environ.get("MAX_RESULTS_V4", str(DEFAULT_MAX_RES)))  # IPv4 保留数量
MAX_RESULTS_V6 = int(os.environ.get("MAX_RESULTS_V6", str(DEFAULT_MAX_RES)))  # IPv6 保留数量
THREADS = int(os.environ.get("SCAN_THREADS", "100"))
VERIFY_ROUNDS = int(os.environ.get("VERIFY_ROUNDS", "3"))
VERIFY_CANDIDATES = int(os.environ.get("VERIFY_CANDIDATES", "100"))

# 质量过滤阈值
MAX_LATENCY = int(os.environ.get("MAX_LATENCY", "300"))   # 最大延迟 ms

# 证书验证模式 (strict / none)
CERT_VERIFY_MODE = os.environ.get("CERT_VERIFY_MODE", "strict")

# IPv6 支持
ENABLE_IPV6 = os.environ.get("ENABLE_IPV6", "false").lower() == "true"

# 测速配置
ENABLE_SPEED_TEST = os.environ.get("ENABLE_SPEED_TEST", "true").lower() == "true"
SPEED_TEST_HOST = os.environ.get("SPEED_TEST_HOST", "speed.cloudflare.com")
SPEED_TEST_TIMEOUT = int(os.environ.get("SPEED_TEST_TIMEOUT", "5"))  # 秒
MIN_DOWNLOAD_SPEED = float(os.environ.get("MIN_DOWNLOAD_SPEED", "10"))  # Mbps

# 优先地区（排在前面）
PRIORITY_REGIONS = ["HK", "MO", "TW", "JP", "SG", "DE", "GB", "US"]


def resolve_domain(domain):
    """解析域名获取所有 IP（支持 IPv4 和 IPv6）"""
    ips = {"ipv4": [], "ipv6": []}
    try:
        results = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        ips["ipv4"] = list(set(str(r[4][0]) for r in results if not PRIVATE_IP_REGEX.match(str(r[4][0]))))
    except Exception:
        pass
    
    if ENABLE_IPV6:
        try:
            results = socket.getaddrinfo(domain, 443, socket.AF_INET6, socket.SOCK_STREAM)
            ips["ipv6"] = list(set(str(r[4][0]) for r in results))
        except Exception:
            pass
    
    return ips


def check_cert_matches_domain(tls_sock, expected_host):
    """检查 TLS 证书 SAN/CN 是否匹配预期域名（纯 Python 解析，零子进程开销）"""
    try:
        cert = tls_sock.getpeercert()
        if not cert:
            return True
        domains = []
        for item in cert.get('subjectAltName', ()):
            if item[0] == 'DNS':
                domains.append(item[1])
        if not domains:
            for item in cert.get('subject', ()):
                for k, v in item:
                    if k == 'commonName':
                        domains.append(v)
        for domain in domains:
            if domain == expected_host:
                return True
            if domain.startswith('*.') and expected_host.endswith(domain[1:]):
                return True
            if domain.startswith('*.'):
                parent = domain[2:]
                parts = expected_host.split('.')
                if len(parts) >= 2 and '.'.join(parts[1:]) == parent:
                    return True
        return False
    except Exception:
        return True


def test_speed(ip, port=443, ipv6=False):
    """通过代理目标 IP 进行实际 TLS/HTTP 下载测速 (Mbps)"""
    if not ENABLE_SPEED_TEST:
        return None
    
    host = SPEED_TEST_HOST
    path = "/__down?bytes=1048576"  # 1MB
    
    sock = None
    try:
        if ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        sock.settimeout(SPEED_TEST_TIMEOUT)
        sock.connect((ip, port))
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        tls_sock = ctx.wrap_socket(sock, server_hostname=host)
        
        req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        tls_sock.sendall(req.encode())
        
        res = b""
        header_found = False
        body_len = 0
        t0 = time.time()
        while True:
            chunk = tls_sock.recv(32768)
            if not chunk:
                break
            if not header_found:
                res += chunk
                idx = res.find(b"\r\n\r\n")
                if idx != -1:
                    header_found = True
                    body_len += len(res[idx+4:])
            else:
                body_len += len(chunk)
            if time.time() - t0 > SPEED_TEST_TIMEOUT:
                break
        t1 = time.time()
        tls_sock.close()
        
        duration = t1 - t0
        if duration > 0 and body_len > 0:
            speed_mbps = round((body_len * 8) / (duration * 1000000), 2)
            return speed_mbps
        return None
    except Exception:
        if sock:
            try:
                sock.close()
            except Exception:
                pass
        return None


def test_proxyip(ip, port=443, ipv6=False):
    """测试 IP 是否可用作 ProxyIP（TLS 握手到 CF 站点），检测人机验证、1034 错误和状态码"""
    test_domains_env = os.environ.get("TEST_DOMAINS", "")
    if test_domains_env:
        test_hosts = [d.strip() for d in test_domains_env.split(",") if d.strip()]
    else:
        test_hosts = ["dash.cloudflare.com", "www.cloudflare.com", "cdnjs.cloudflare.com", "cloudflare.com"]
    test_host = random.choice(test_hosts)
    start_time = time.time()
    sock = None
    try:
        if ipv6:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))
        
        ctx = ssl.create_default_context()
        if CERT_VERIFY_MODE == "strict":
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        
        tls_sock = ctx.wrap_socket(sock, server_hostname=test_host)
        latency = round((time.time() - start_time) * 1000)

        # 检查证书匹配
        if CERT_VERIFY_MODE == "strict":
            if not check_cert_matches_domain(tls_sock, test_host):
                tls_sock.close()
                return None

        # 发送 HTTP 请求测试
        request = f"GET / HTTP/1.1\r\nHost: {test_host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
        tls_sock.sendall(request.encode())

        response = b""
        try:
            while True:
                chunk = tls_sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\r\n\r\n" in response:
                    break
        except socket.timeout:
            pass

        tls_sock.close()

        headers = response.decode("utf-8", errors="ignore").lower()
        if "cf-mitigated: challenge" in headers:
            return None

        if "error 1034" in headers or "边缘ip受限" in headers:
            return None

        # 检查 HTTP 异常状态码 (403/400 及 Cloudflare 5xx 错误)
        status_line = headers.split("\r\n")[0] if "\r\n" in headers else headers
        if any(f" {code} " in status_line for code in (400, 403, 500, 501, 502, 503, 504, 520, 521, 522, 523, 524, 525, 526)):
            return None

        return {"latency": latency, "ipv6": ipv6}
    except ssl.SSLCertVerificationError:
        return None
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def resolve_all_upstreams():
    """并发解析所有上游域名，去重（支持 IPv4 和 IPv6）"""
    print("[*] 并发解析上游 ProxyIP 域名...")
    all_ips = {"ipv4": set(), "ipv6": set()}
    
    domains_to_resolve = list(UPSTREAM_DOMAINS)
    if ENABLE_IPV6:
        domains_to_resolve.extend(UPSTREAM_DOMAINS_V6)
    
    with ThreadPoolExecutor(max_workers=min(20, len(domains_to_resolve))) as executor:
        futures = {executor.submit(resolve_domain, domain): domain for domain in domains_to_resolve}
        for future in as_completed(futures):
            domain = futures[future]
            try:
                ips = future.result()
                if ips["ipv4"]:
                    print(f"  [+] {domain} -> IPv4: {len(ips['ipv4'])} 个")
                    all_ips["ipv4"].update(ips["ipv4"])
                if ips["ipv6"]:
                    print(f"  [+] {domain} -> IPv6: {len(ips['ipv6'])} 个")
                    all_ips["ipv6"].update(ips["ipv6"])
                if not ips["ipv4"] and not ips["ipv6"]:
                    print(f"  [-] {domain} -> 解析无结果")
            except Exception as e:
                print(f"  [-] {domain} -> 解析出错: {e}")
    
    total = len(all_ips["ipv4"]) + len(all_ips["ipv6"])
    print(f"\n[*] 共获取 {total} 个去重 IP (IPv4: {len(all_ips['ipv4'])}, IPv6: {len(all_ips['ipv6'])})")
    return all_ips


def collect_from_apis():
    """从社区 API 数据源采集 CF IP（纯 stdlib，带私有网段过滤）"""
    print("\n[*] 从 API 数据源采集 CF IP...")
    all_ips = {"ipv4": set(), "ipv6": set()}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,*/*",
    }
    for url in API_SOURCES:
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
            
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
            valid = [ip for ip in ips if all(0 <= int(p) <= 255 for p in ip.split('.')) and not PRIVATE_IP_REGEX.match(ip)]
            
            if not valid:
                for line in text.strip().split('\n'):
                    line = line.strip()
                    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', line):
                        if all(0 <= int(p) <= 255 for p in line.split('.')) and not PRIVATE_IP_REGEX.match(line):
                            valid.append(line)
            
            v6s = re.findall(r'(?:[0-9a-fA-F]{1,4}:){2,}[0-9a-fA-F]{1,4}', text)
            before = len(all_ips["ipv4"])
            all_ips["ipv4"].update(valid)
            all_ips["ipv6"].update(v6s)
            new = len(all_ips["ipv4"]) - before
            print(f"  [+] {url.split('/')[2]} -> IPv4: {new} 新 / {len(valid)} 总")
            time.sleep(0.1)
        except Exception as e:
            print(f"  [-] {url.split('/')[2]} -> 失败: {e}")
    total = len(all_ips["ipv4"]) + len(all_ips["ipv6"])
    print(f"[*] API 源共获取 {total} 个去重 IP (IPv4: {len(all_ips['ipv4'])}, IPv6: {len(all_ips['ipv6'])})")
    return all_ips


def initial_test(ip_list):
    """第一轮：快速筛选可用 IP"""
    print(f"[*] 初筛测试...")
    results = []
    completed = 0
    
    tasks = []
    for ip in ip_list["ipv4"]:
        tasks.append((ip, False))
    for ip in ip_list["ipv6"]:
        tasks.append((ip, True))
    
    total = len(tasks)
    print(f"  共 {total} 个 IP 待测试")
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(test_proxyip, ip, 443, ipv6): (ip, ipv6) for ip, ipv6 in tasks}
        for future in as_completed(futures):
            completed += 1
            if completed % 200 == 0 or completed == total:
                print(f"  [*] 进度: {completed}/{total}")
            result = future.result()
            if result:
                ip, ipv6 = futures[future]
                results.append({
                    "ip": ip,
                    "latency": result["latency"],
                    "ipv6": result["ipv6"]
                })
    results.sort(key=lambda x: x["latency"])
    print(f"[+] 初筛通过: {len(results)} 个")
    return results


def verify_single_ip(ip, ipv6=False):
    """对单个 IP 做多轮复验"""
    latencies = []
    for i in range(VERIFY_ROUNDS):
        result = test_proxyip(ip, 443, ipv6)
        if result is None:
            return None
        latencies.append(result["latency"])
        if i < VERIFY_ROUNDS - 1:
            time.sleep(0.2)
    
    avg_latency = round(sum(latencies) / len(latencies))
    jitter = max(latencies) - min(latencies)
    
    return {
        "ip": ip,
        "avg_latency": avg_latency,
        "jitter": jitter,
        "ipv6": ipv6,
        "rounds": latencies
    }


def verify_candidates(candidates):
    """第二轮：多轮复验候选 IP"""
    count = min(len(candidates), VERIFY_CANDIDATES)
    top_ips = [(c["ip"], c.get("ipv6", False)) for c in candidates[:count]]
    print(f"\n[*] 复验 top {count} 候选（每个测 {VERIFY_ROUNDS} 轮）...")

    verified = []
    with ThreadPoolExecutor(max_workers=min(50, count)) as executor:
        futures = {executor.submit(verify_single_ip, ip, ipv6): (ip, ipv6) for ip, ipv6 in top_ips}
        for future in as_completed(futures):
            result = future.result()
            ip, ipv6 = futures[future]
            if result:
                verified.append(result)
                print(f"  [✓] {ip} {'(IPv6)' if ipv6 else ''} - avg {result['avg_latency']}ms jitter {result['jitter']}ms {result['rounds']}")
            else:
                print(f"  [✗] {ip} {'(IPv6)' if ipv6 else ''} - 复验失败")

    verified.sort(key=lambda x: x["avg_latency"])
    print(f"\n[+] 复验通过: {len(verified)}/{count} 个")
    return verified


GEO_CACHE = {}

def get_geo_info(ip):
    """获取 IP 地理位置"""
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    
    url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            info = {
                "country": data.get("country", "Unknown"),
                "countryCode": data.get("countryCode", "??"),
                "city": data.get("city", "Unknown"),
                "isp": data.get("isp", "Unknown"),
            }
            GEO_CACHE[ip] = info
            return info
    except Exception:
        pass
            
    default_info = {"country": "Unknown", "countryCode": "??", "city": "Unknown", "isp": "Unknown"}
    GEO_CACHE[ip] = default_info
    return default_info


def update_cf_dns(results):
    """更新 Cloudflare DNS 记录"""
    cf_token = os.environ.get("CF_API_TOKEN")
    cf_zone_id = os.environ.get("CF_ZONE_ID")
    cf_domain = os.environ.get("CF_DOMAIN")
    record_name = os.environ.get("CF_RECORD_NAME", "proxyip")
    cf_email = os.environ.get("CF_EMAIL", "")

    if not all([cf_token, cf_zone_id, cf_domain]):
        print("[!] 缺少 Cloudflare 配置，跳过 DNS 更新")
        return False

    full_domain = f"{record_name}.{cf_domain}"

    headers = {"Content-Type": "application/json"}
    if cf_token and cf_email:
        headers["X-Auth-Email"] = cf_email
        headers["X-Auth-Key"] = cf_token
    elif cf_token:
        headers["Authorization"] = f"Bearer {cf_token}"

    ipv4_ips = [r["ip"] for r in results if not r.get("ipv6")]
    ipv6_ips = [r["ip"] for r in results if r.get("ipv6")]

    print(f"\n[*] 更新 DNS: {full_domain}")
    print(f"    IPv4: {len(ipv4_ips)} 个")
    print(f"    IPv6: {len(ipv6_ips)} 个")

    url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records?name={full_domain}&type=A"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            existing_records = data.get("result", [])
    except Exception as e:
        print(f"[!] 获取 A 记录失败: {e}")
        existing_records = []

    for record in existing_records:
        del_url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records/{record['id']}"
        del_req = urllib.request.Request(del_url, headers=headers, method="DELETE")
        try:
            urllib.request.urlopen(del_req)
            print(f"    删除 A: {record['content']}")
        except Exception as e:
            print(f"    删除失败: {e}")

    url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records?name={full_domain}&type=AAAA"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            existing_records = data.get("result", [])
    except Exception as e:
        print(f"[!] 获取 AAAA 记录失败: {e}")
        existing_records = []

    for record in existing_records:
        del_url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records/{record['id']}"
        del_req = urllib.request.Request(del_url, headers=headers, method="DELETE")
        try:
            urllib.request.urlopen(del_req)
            print(f"    删除 AAAA: {record['content']}")
        except Exception as e:
            print(f"    删除失败: {e}")

    success_count = 0
    for ip in ipv4_ips:
        create_url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records"
        payload = json.dumps({
            "type": "A",
            "name": full_domain,
            "content": ip,
            "ttl": 60,
            "proxied": False,
        }).encode()
        create_req = urllib.request.Request(create_url, data=payload, headers=headers, method="POST")
        try:
            urllib.request.urlopen(create_req)
            print(f"    添加 A: {full_domain} -> {ip}")
            success_count += 1
        except Exception as e:
            print(f"    添加失败: {e}")

    for ip in ipv6_ips:
        create_url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records"
        payload = json.dumps({
            "type": "AAAA",
            "name": full_domain,
            "content": ip,
            "ttl": 60,
            "proxied": False,
        }).encode()
        create_req = urllib.request.Request(create_url, data=payload, headers=headers, method="POST")
        try:
            urllib.request.urlopen(create_req)
            print(f"    添加 AAAA: {full_domain} -> {ip}")
            success_count += 1
        except Exception as e:
            print(f"    添加失败: {e}")

    print(f"\n[+] DNS 更新完成: {success_count}/{len(ipv4_ips) + len(ipv6_ips)}")
    return True


def save_results(results):
    """保存结果"""
    output = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "count": len(results),
        "ips": results,
    }
    with open("proxyip-results.json", "w") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    with open("proxyip-list.txt", "w") as f:
        for r in results:
            f.write(f"{r['ip']}\n")
    print("[+] 结果已保存")


def main():
    print("=" * 60)
    print("  ProxyIP Resolver - 高效极速版（含真实下载测速、纯 Python 证书验证、GeoIP 控频）")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print(f"  配置: top {VERIFY_CANDIDATES} 候选, {VERIFY_ROUNDS} 轮复验")
    print(f"  保留: IPv4 {MAX_RESULTS_V4} 个, IPv6 {MAX_RESULTS_V6} 个")
    print(f"  质量: 延迟<={MAX_LATENCY}ms, 无人机验证, 无 1034 / 状态码错误")
    print(f"  证书验证: {CERT_VERIFY_MODE}")
    print(f"  IPv6: {'启用' if ENABLE_IPV6 else '禁用'}")
    print(f"  测速: {'启用' if ENABLE_SPEED_TEST else '禁用'}")
    if ENABLE_SPEED_TEST:
        print(f"  最低速度: {MIN_DOWNLOAD_SPEED}Mbps")
    print(f"  优先地区: {', '.join(PRIORITY_REGIONS)}")
    print("=" * 60)

    # 1. 解析所有上游域名
    all_ips = resolve_all_upstreams()

    # 1.5. 从 API 数据源采集更多 IP
    api_ips = collect_from_apis()
    all_ips["ipv4"].update(api_ips["ipv4"])
    all_ips["ipv6"].update(api_ips["ipv6"])
    total = len(all_ips["ipv4"]) + len(all_ips["ipv6"])
    print(f"\n[*] 合并后共 {total} 个去重 IP (IPv4: {len(all_ips['ipv4'])}, IPv6: {len(all_ips['ipv6'])})")

    if not all_ips["ipv4"] and not all_ips["ipv6"]:
        print("[!] 未获取到任何 IP，退出")
        sys.exit(1)

    # 2. 初筛：单次测试，选出候选
    initial_results = initial_test(all_ips)
    if not initial_results:
        print("[!] 初筛无可用 IP，退出")
        sys.exit(1)

    # 3. 复验：每个候选测多轮，淘汰不稳定 IP
    verified = verify_candidates(initial_results)
    if not verified:
        print("[!] 复验后无可用 IP，退出")
        sys.exit(1)

    # 4. 质量过滤：延迟超标直接淘汰
    filtered = [r for r in verified if r["avg_latency"] <= MAX_LATENCY]
    print(f"\n[*] 质量过滤: {len(verified)} -> {len(filtered)} (延迟<={MAX_LATENCY}ms)")
    if not filtered:
        print("[!] 质量过滤后无可用 IP，放宽标准使用全部")
        filtered = verified

    # 5. 针对高质量前 N 个候选 IP 做真实 ProxyIP 下载测速
    if ENABLE_SPEED_TEST:
        test_candidates = filtered[:30]
        print(f"\n[*] 开始对 top {len(test_candidates)} 候选 IP 做 ProxyIP 实际代理下载测速 (目标 >= {MIN_DOWNLOAD_SPEED}Mbps)...")
        speed_tested = []
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(test_speed, r["ip"], 443, r.get("ipv6", False)): r for r in test_candidates}
            for future in as_completed(futures):
                item = futures[future]
                speed = future.result()
                item["speed"] = speed
                if speed:
                    print(f"  [+] {item['ip']} 测速结果: {speed} Mbps")
                    speed_tested.append(item)
                else:
                    print(f"  [-] {item['ip']} 测速超时或无响应")

        # 合并已测速和未测速的高质量列表
        speed_filtered = [r for r in speed_tested if r.get("speed") and r["speed"] >= MIN_DOWNLOAD_SPEED]
        if speed_filtered:
            print(f"[*] 速度过滤: {len(test_candidates)} -> {len(speed_filtered)} (速度>={MIN_DOWNLOAD_SPEED}Mbps)")
            # 补全后续不需要测速的优秀 IP 备用
            remaining = [r for r in filtered if r not in test_candidates]
            filtered = speed_filtered + remaining
        elif speed_tested:
            print("[!] 满足最低速阈值的 IP 较少，使用所有测速成功的 IP")
            remaining = [r for r in filtered if r not in test_candidates]
            filtered = speed_tested + remaining
        else:
            print("[!] 测速未完成或接口限制，保留基于延迟的可用 IP")

    # 6. 只对最终选出的前 N 个候选 IP 获取地理位置（精细风控，防止触发 API 限流）
    top_candidates = filtered[:(MAX_RESULTS_V4 + MAX_RESULTS_V6)]
    print(f"\n[*] 并发获取 {len(top_candidates)} 个精选 IP 的地理位置...")
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(get_geo_info, r["ip"]): r for r in top_candidates}
        for future in as_completed(futures):
            item = futures[future]
            item["geo"] = future.result()

    # 7. 地区优先排序：优先地区排前面，同地区按延迟排序
    def region_priority(item):
        code = item.get("geo", {}).get("countryCode", "ZZ")
        try:
            return PRIORITY_REGIONS.index(code)
        except ValueError:
            return len(PRIORITY_REGIONS)

    top_candidates.sort(key=lambda x: (region_priority(x), x["avg_latency"]))

    # 8. 取 top N（IPv4 和 IPv6 分开）
    final_v4 = [r for r in top_candidates if not r.get("ipv6")][:MAX_RESULTS_V4]
    final_v6 = [r for r in top_candidates if r.get("ipv6")][:MAX_RESULTS_V6]
    final = final_v4 + final_v6

    # 9. 打印最终结果
    print(f"\n[*] 最终 {len(final)} 个 IP (IPv4: {len(final_v4)}, IPv6: {len(final_v6)}):")
    for i, r in enumerate(final):
        geo = r.get("geo", {})
        country_code = geo.get("countryCode", "??")
        city = geo.get("city", "Unknown")
        priority_mark = "★" if country_code in PRIORITY_REGIONS else " "
        ipv6_mark = " (IPv6)" if r.get("ipv6") else ""
        speed_str = f" speed {r['speed']}Mbps" if r.get("speed") else ""
        print(f"    {priority_mark} {r['ip']}{ipv6_mark} - {country_code} {city} - avg {r['avg_latency']}ms jitter {r['jitter']}ms{speed_str}")

    # 10. 保存
    save_results(final)

    # 11. 更新 DNS
    if os.environ.get("CF_API_TOKEN"):
        update_cf_dns(final)
    else:
        print("\n[!] 未配置 CF_API_TOKEN，跳过 DNS 更新")

    # 12. 更新 Worker（如果配置了）
    worker_url = os.environ.get("WORKER_URL")
    worker_token = os.environ.get("WORKER_UPDATE_TOKEN")
    if worker_url and worker_token:
        try:
            ips = [r["ip"] for r in final]
            payload = json.dumps({"ips": ips}).encode()
            req = urllib.request.Request(
                f"{worker_url}/update",
                data=payload,
                headers={
                    "Authorization": f"Bearer {worker_token}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
                print(f"[+] Worker 已更新: {data.get('count', 0)} 个 IP")
        except Exception as e:
            print(f"[!] Worker 更新失败: {e}")

    print("\n[+] 完成!")


if __name__ == "__main__":
    main()
