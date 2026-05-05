#!/usr/bin/env python3
"""
ProxyIP Resolver - 解析多个社区 ProxyIP 域名，聚合可用 IP 更新 DNS
"""

import socket
import ssl
import time
import json
import sys
import os
import random
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# 社区 ProxyIP 域名列表（越多越好，互为兜底）
UPSTREAM_DOMAINS = [
    "proxyip.cmliussss.net",
    "proxyip.us.cmliussss.net",
    "proxyip.hw.090227.xyz",
    "cdn.xn--b6gac.eu.org",
    "cdn-all.edtunnel.ml",
    "proxyip.fxxk.dedyn.io",
    "proxyip.sg.cmliussss.net",
    "proxyip.jp.cmliussss.net",
    "proxyip.de.cmliussss.net",
    "proxyip.hk.cmliussss.net",
]

# GitHub Actions 环境变量
TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", "5"))
MAX_RESULTS = int(os.environ.get("MAX_RESULTS", "30"))
THREADS = int(os.environ.get("SCAN_THREADS", "100"))


def resolve_domain(domain):
    """解析域名获取所有 IP"""
    try:
        results = socket.getaddrinfo(domain, 443, socket.AF_INET, socket.SOCK_STREAM)
        ips = list(set(r[4][0] for r in results))
        return ips
    except Exception as e:
        print(f"  [!] 解析失败: {domain} - {e}")
        return []


def test_proxyip(ip, port=443):
    """测试 IP 是否可用作 ProxyIP（尝试 TLS 连接到 CF 站点）"""
    test_hosts = [
        "www.cloudflare.com",
        "cdnjs.cloudflare.com",
        "cloudflare.com",
    ]
    test_host = random.choice(test_hosts)
    start_time = time.time()
    sock = None

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, port))

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        tls_sock = ctx.wrap_socket(sock, server_hostname=test_host)
        latency = round((time.time() - start_time) * 1000)

        # 验证证书（不验证主机名，但检查 TLS 握手成功）
        tls_sock.close()

        return {
            'ip': ip,
            'port': port,
            'latency': latency,
            'test_host': test_host,
            'status': 'ok'
        }
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def get_geo_info(ip):
    """获取 IP 地理位置"""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,countryCode,city,isp"
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            return {
                'country': data.get('country', 'Unknown'),
                'countryCode': data.get('countryCode', '??'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown')
            }
    except Exception:
        return {'country': 'Unknown', 'countryCode': '??', 'city': 'Unknown', 'isp': 'Unknown'}


def resolve_all_upstreams():
    """解析所有上游域名，去重"""
    print("[*] 解析上游 ProxyIP 域名...")
    all_ips = set()

    for domain in UPSTREAM_DOMAINS:
        ips = resolve_domain(domain)
        if ips:
            print(f"  [+] {domain} -> {len(ips)} 个 IP")
            all_ips.update(ips)
        else:
            print(f"  [-] {domain} -> 解析失败")

    print(f"\n[*] 共获取 {len(all_ips)} 个去重 IP")
    return list(all_ips)


def test_all_ips(ip_list):
    """并行测试所有 IP"""
    print(f"[*] 测试 IP 可用性（线程: {THREADS}，超时: {TIMEOUT}s）...")
    results = []
    completed = 0

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(test_proxyip, ip): ip for ip in ip_list}

        for future in as_completed(futures):
            completed += 1
            if completed % 50 == 0:
                print(f"  [*] 进度: {completed}/{len(ip_list)}，已找到 {len(results)} 个可用")

            result = future.result()
            if result:
                results.append(result)

    results.sort(key=lambda x: x['latency'])
    print(f"\n[+] 测试完成，{len(results)}/{len(ip_list)} 个可用")

    for r in results[:10]:
        print(f"    {r['ip']}:{r['port']} - {r['latency']}ms")

    return results


def update_cf_dns(results):
    """更新 Cloudflare DNS 记录"""
    cf_token = os.environ.get('CF_API_TOKEN')
    cf_zone_id = os.environ.get('CF_ZONE_ID')
    cf_domain = os.environ.get('CF_DOMAIN')
    record_name = os.environ.get('CF_RECORD_NAME', 'proxyip')
    cf_email = os.environ.get('CF_EMAIL', '')

    if not all([cf_token, cf_zone_id, cf_domain]):
        print("[!] 缺少 Cloudflare 配置，跳过 DNS 更新")
        return False

    full_domain = f"{record_name}.{cf_domain}"

    headers = {'Content-Type': 'application/json'}
    if cf_token and cf_email:
        headers['X-Auth-Email'] = cf_email
        headers['X-Auth-Key'] = cf_token
    elif cf_token:
        headers['Authorization'] = f'Bearer {cf_token}'

    # 获取现有记录
    url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records?name={full_domain}&type=A"
    req = urllib.request.Request(url, headers=headers)

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
            existing_records = data.get('result', [])
    except Exception as e:
        print(f"[!] 获取 DNS 记录失败: {e}")
        return False

    # 取延迟最低的 N 个 IP
    best_ips = [r['ip'] for r in results[:MAX_RESULTS]]

    if not best_ips:
        print("[!] 没有可用 IP，跳过 DNS 更新")
        return False

    print(f"\n[*] 更新 DNS: {full_domain}")
    print(f"[*] 使用 {len(best_ips)} 个 IP")

    # 删除旧记录
    for record in existing_records:
        del_url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records/{record['id']}"
        del_req = urllib.request.Request(del_url, headers=headers, method='DELETE')
        try:
            urllib.request.urlopen(del_req)
            print(f"    删除: {record['content']}")
        except Exception as e:
            print(f"    删除失败: {e}")

    # 添加新记录（每个 IP 单独一条 A 记录）
    success_count = 0
    for ip in best_ips:
        create_url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records"
        payload = json.dumps({
            'type': 'A',
            'name': full_domain,
            'content': ip,
            'ttl': 60,
            'proxied': False  # 灰色云朵！
        }).encode()

        create_req = urllib.request.Request(create_url, data=payload, headers=headers, method='POST')
        try:
            urllib.request.urlopen(create_req)
            print(f"    添加: {full_domain} -> {ip}")
            success_count += 1
        except Exception as e:
            print(f"    添加失败: {e}")

    print(f"\n[+] DNS 更新完成: {success_count}/{len(best_ips)} 条记录")
    return True


def save_results(results):
    """保存结果"""
    output = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        'count': len(results),
        'ips': results
    }

    with open('proxyip-results.json', 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    with open('proxyip-list.txt', 'w') as f:
        for r in results:
            f.write(f"{r['ip']}\n")

    print(f"[+] 结果已保存")


def main():
    print("=" * 60)
    print("  ProxyIP Resolver - 从社区聚合可用 IP")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("=" * 60)

    # 1. 解析所有上游域名
    all_ips = resolve_all_upstreams()
    if not all_ips:
        print("[!] 未获取到任何 IP，退出")
        sys.exit(1)

    # 2. 测试所有 IP
    results = test_all_ips(all_ips)
    if not results:
        print("[!] 没有可用 IP，退出")
        sys.exit(1)

    # 3. 获取前 10 个 IP 的地理位置
    print("\n[*] 获取地理位置...")
    for r in results[:10]:
        geo = get_geo_info(r['ip'])
        r['geo'] = geo
        print(f"    {r['ip']} - {geo['countryCode']} {geo['city']} ({geo['isp']}) - {r['latency']}ms")

    # 4. 保存结果
    save_results(results)

    # 5. 更新 DNS
    if os.environ.get('CF_API_TOKEN'):
        update_cf_dns(results)
    else:
        print("\n[!] 未配置 CF_API_TOKEN，跳过 DNS 更新")

    # 6. 更新 Worker（如果配置了）
    worker_url = os.environ.get('WORKER_URL')
    worker_token = os.environ.get('WORKER_UPDATE_TOKEN')
    if worker_url and worker_token:
        try:
            ips = [r['ip'] for r in results]
            payload = json.dumps({'ips': ips}).encode()
            req = urllib.request.Request(
                f"{worker_url}/update",
                data=payload,
                headers={
                    'Authorization': f'Bearer {worker_token}',
                    'Content-Type': 'application/json',
                },
                method='POST'
            )
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read())
                print(f"[+] Worker 已更新: {data.get('count', 0)} 个 IP")
        except Exception as e:
            print(f"[!] Worker 更新失败: {e}")

    print("\n[+] 完成!")


if __name__ == '__main__':
    main()
