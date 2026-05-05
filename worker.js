/**
 * Cloudflare Worker - ProxyIP Resolver
 * 
 * 每次请求随机返回一个可用的 ProxyIP
 * edgetunnel 的 PROXYIP 填这个 Worker 的地址
 * 
 * 部署方法：
 * 1. 在 CF 后台创建 Worker
 * 2. 创建 KV 命名空间，绑定到 WORKER_KV
 * 3. 把代码粘贴到 Worker 编辑器
 * 4. 设置路由或自定义域名
 */

// 如果没有 KV，可以直接用这个硬编码列表（由 scanner 自动更新）
let PROXY_IPS = [
  // 由 scanner.py 自动填充
];

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    
    // 管理接口：更新 IP 列表
    if (url.pathname === '/update' && request.method === 'POST') {
      const authHeader = request.headers.get('Authorization');
      if (authHeader !== `Bearer ${env.UPDATE_TOKEN}`) {
        return new Response('Unauthorized', { status: 401 });
      }
      
      const body = await request.json();
      if (body.ips && Array.isArray(body.ips)) {
        // 保存到 KV
        if (env.WORKER_KV) {
          await env.WORKER_KV.put('proxy_ips', JSON.stringify(body.ips));
        }
        PROXY_IPS = body.ips;
        return new Response(JSON.stringify({ 
          success: true, 
          count: body.ips.length 
        }), {
          headers: { 'Content-Type': 'application/json' }
        });
      }
      return new Response('Invalid body', { status: 400 });
    }
    
    // 状态接口
    if (url.pathname === '/status') {
      let ips = PROXY_IPS;
      if (env.WORKER_KV) {
        const stored = await env.WORKER_KV.get('proxy_ips');
        if (stored) ips = JSON.parse(stored);
      }
      return new Response(JSON.stringify({
        count: ips.length,
        timestamp: new Date().toISOString()
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // IP 列表接口
    if (url.pathname === '/list') {
      let ips = PROXY_IPS;
      if (env.WORKER_KV) {
        const stored = await env.WORKER_KV.get('proxy_ips');
        if (stored) ips = JSON.parse(stored);
      }
      return new Response(ips.join('\n'), {
        headers: { 'Content-Type': 'text/plain' }
      });
    }
    
    // 默认：返回随机 ProxyIP（供 edgetunnel 使用）
    let ips = PROXY_IPS;
    if (env.WORKER_KV) {
      const stored = await env.WORKER_KV.get('proxy_ips');
      if (stored) ips = JSON.parse(stored);
    }
    
    if (ips.length === 0) {
      return new Response('No ProxyIP available', { status: 503 });
    }
    
    // 随机返回一个 IP
    const randomIP = ips[Math.floor(Math.random() * ips.length)];
    return new Response(randomIP, {
      headers: { 
        'Content-Type': 'text/plain',
        'Access-Control-Allow-Origin': '*'
      }
    });
  }
};
