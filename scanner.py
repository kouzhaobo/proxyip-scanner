#!/usr/bin/env python3
"""
Cloudflare ProxyIP Scanner
扫描 Cloudflare IP 段，找出可用的 ProxyIP 并更新 DNS
"""

import socket
import ssl
import time
import json
import sys
import os
import struct
import random
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

# Cloudflare 常见可用 IP 段 (已知可用作 ProxyIP 的范围)
CF_IP_RANGES = [
    # 经典 ProxyIP 范围
    "172.64.0.0/13",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.67.0.0/16",
    "104.20.0.0/15",
    "188.114.96.0/20",
    "190.93.240.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "108.162.192.0/18",
    "141.101.64.0/18",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "131.0.72.0/22",
]

# 测试目标：一个 CF 托管的站点
TEST_HOSTS = [
    "www.cloudflare.com",
    "cdnjs.cloudflare.com",
    "cloudflare.com",
]

# GitHub Actions 环境变量
THREADS = int(os.environ.get("SCAN_THREADS", "200"))
TIMEOUT = float(os.environ.get("SCAN_TIMEOUT", "3"))
MAX_RESULTS = int(os.environ.get("MAX_RESULTS", "50"))
PORT = 443


def ip_to_int(ip):
    parts = list(map(int, ip.split('.')))
    return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]


def int_to_ip(n):
    return f"{(n >> 24) & 0xFF}.{(n >> 16) & 0xFF}.{(n >> 8) & 0xFF}.{n & 0xFF}"


def expand_cidr(cidr):
    """展开 CIDR 为 IP 列表"""
    ip, prefix = cidr.split('/')
    prefix = int(prefix)
    start = ip_to_int(ip) & (0xFFFFFFFF << (32 - prefix))
    end = start + (1 << (32 - prefix)) - 1
    
    # 对于大范围，随机采样
    total = end - start + 1
    if total > 256:
        ips = set()
        while len(ips) < min(256, total):
            ips.add(int_to_ip(random.randint(start, end)))
        return list(ips)
    return [int_to_ip(i) for i in range(start, end + 1)]


def test_proxyip(ip, test_host=None):
    """测试一个 IP 是否可以作为 ProxyIP"""
    if test_host is None:
        test_host = random.choice(TEST_HOSTS)
    
    start_time = time.time()
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, PORT))
        
        # 发送 HTTP CONNECT 请求模拟
        connect_req = f"CONNECT {test_host}:443 HTTP/1.1\r\nHost: {test_host}:443\r\n\r\n"
        sock.sendall(connect_req.encode())
        
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        latency = round((time.time() - start_time) * 1000)
        
        if '200' in response:
            return {
                'ip': ip,
                'latency': latency,
                'status': 'ok',
                'test_host': test_host
            }
        
        # 尝试 TLS 直连方式
        sock.close()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((ip, PORT))
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        tls_sock = ctx.wrap_socket(sock, server_hostname=test_host)
        latency = round((time.time() - start_time) * 1000)
        tls_sock.close()
        
        return {
            'ip': ip,
            'latency': latency,
            'status': 'ok_tls',
            'test_host': test_host
        }
        
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def scan_all():
    """扫描所有 IP 段"""
    print(f"[*] 开始扫描，线程数: {THREADS}，超时: {TIMEOUT}s")
    
    # 展开所有 IP
    all_ips = []
    for cidr in CF_IP_RANGES:
        ips = expand_cidr(cidr)
        all_ips.extend(ips)
    
    print(f"[*] 共 {len(all_ips)} 个 IP 待扫描")
    
    results = []
    completed = 0
    
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = {executor.submit(test_proxyip, ip): ip for ip in all_ips}
        
        for future in as_completed(futures):
            completed += 1
            if completed % 500 == 0:
                print(f"[*] 进度: {completed}/{len(all_ips)}，已找到 {len(results)} 个可用 IP")
            
            result = future.result()
            if result:
                results.append(result)
                if len(results) >= MAX_RESULTS * 3:
                    # 找够了，取消剩余任务
                    for f in futures:
                        f.cancel()
                    break
    
    # 按延迟排序，取前 N 个
    results.sort(key=lambda x: x['latency'])
    results = results[:MAX_RESULTS]
    
    print(f"\n[+] 扫描完成，找到 {len(results)} 个可用 ProxyIP:")
    for r in results:
        print(f"    {r['ip']} - {r['latency']}ms ({r['test_host']})")
    
    return results


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


def update_cf_dns(results):
    """更新 Cloudflare DNS 记录"""
    cf_token = os.environ.get('CF_API_TOKEN')
    cf_zone_id = os.environ.get('CF_ZONE_ID')
    cf_domain = os.environ.get('CF_DOMAIN')
    record_name = os.environ.get('CF_RECORD_NAME', 'proxyip')
    
    if not all([cf_token, cf_zone_id, cf_domain]) and not os.environ.get('CF_EMAIL'):
        print("[!] 缺少 Cloudflare 配置，跳过 DNS 更新")
        print("[!] 请设置: CF_API_TOKEN, CF_ZONE_ID, CF_DOMAIN, CF_EMAIL")
        return False
    
    full_domain = f"{record_name}.{cf_domain}"
    
    cf_email = os.environ.get('CF_EMAIL', '')
    headers = {
        'Content-Type': 'application/json',
    }
    if cf_token and cf_email:
        # Global API Key
        headers['X-Auth-Email'] = cf_email
        headers['X-Auth-Key'] = cf_token
    elif cf_token:
        # Bearer Token (API Token)
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
    
    # 选择最优 IP（延迟最低的前 3 个）
    best_ips = [r['ip'] for r in results[:3]]
    
    if not best_ips:
        print("[!] 没有可用 IP，跳过 DNS 更新")
        return False
    
    print(f"\n[*] 更新 DNS: {full_domain}")
    print(f"[*] 使用 IP: {', '.join(best_ips)}")
    
    # 删除旧记录
    for record in existing_records:
        del_url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records/{record['id']}"
        del_req = urllib.request.Request(del_url, headers=headers, method='DELETE')
        try:
            urllib.request.urlopen(del_req)
            print(f"    删除旧记录: {record['content']}")
        except Exception as e:
            print(f"    删除失败: {e}")
    
    # 添加新记录
    for ip in best_ips:
        create_url = f"https://api.cloudflare.com/client/v4/zones/{cf_zone_id}/dns_records"
        payload = json.dumps({
            'type': 'A',
            'name': full_domain,
            'content': ip,
            'ttl': 60,  # 1 分钟 TTL，快速切换
            'proxied': False  # 灰色云朵！
        }).encode()
        
        create_req = urllib.request.Request(create_url, data=payload, headers=headers, method='POST')
        try:
            urllib.request.urlopen(create_req)
            print(f"    添加记录: {full_domain} -> {ip}")
        except Exception as e:
            print(f"    添加失败: {e}")
    
    return True


def save_results(results):
    """保存结果到文件"""
    output = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime()),
        'count': len(results),
        'ips': results
    }
    
    with open('proxyip-results.json', 'w') as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    
    # 同时保存纯文本 IP 列表
    with open('proxyip-list.txt', 'w') as f:
        for r in results:
            f.write(f"{r['ip']}\n")
    
    print(f"\n[+] 结果已保存到 proxyip-results.json 和 proxyip-list.txt")


def main():
    print("=" * 60)
    print("  Cloudflare ProxyIP Scanner")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")
    print("=" * 60)
    
    results = scan_all()
    
    if not results:
        print("[!] 扫描未找到可用 IP")
        sys.exit(1)
    
    # 获取地理位置信息
    print("\n[*] 获取 IP 地理位置...")
    for r in results[:10]:  # 只查前 10 个
        geo = get_geo_info(r['ip'])
        r['geo'] = geo
        print(f"    {r['ip']} - {geo['countryCode']} {geo['city']} ({geo['isp']}) - {r['latency']}ms")
    
    save_results(results)
    
    # 更新 DNS
    if os.environ.get('CF_API_TOKEN'):
        update_cf_dns(results)
    else:
        print("\n[!] 未配置 CF_API_TOKEN，跳过 DNS 更新")
    
    print("\n[+] 完成!")


if __name__ == '__main__':
    main()
