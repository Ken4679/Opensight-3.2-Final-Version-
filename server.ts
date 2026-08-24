import express from 'express';
import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

app.use(express.json());

// In-memory data store for OpenSight
let mockCredentials = {
  hasCredentials: true,
  username: "openvpn-user-cn",
  password: "••••••••••••"
};

interface NodeData {
  nodeId: string;
  serverName: string;
  country: string;
  city: string;
  overallScore: number;
  webScore: number;
  videoScore: number;
  stabilityScore: number;
  bestTcpLatency: number | null;
  isReachable: boolean;
  explanation: string;
  protocol: string;
  port: number;
  lastMeasuredAt: number | null;
}

let mockNodes: NodeData[] = [
  {
    nodeId: "node-jp-free-01",
    serverName: "JP-FREE#1",
    country: "日本",
    city: "Tokyo",
    overallScore: 94,
    webScore: 95,
    videoScore: 92,
    stabilityScore: 96,
    bestTcpLatency: 42,
    isReachable: true,
    explanation: "响应极快（延迟 42ms，抖动 3ms），连接非常稳定，适合网页浏览与实时通讯",
    protocol: "UDP",
    port: 51820,
    lastMeasuredAt: Date.now() - 1000 * 60 * 2,
  },
  {
    nodeId: "node-jp-free-02",
    serverName: "JP-FREE#2",
    country: "日本",
    city: "Osaka",
    overallScore: 89,
    webScore: 90,
    videoScore: 88,
    stabilityScore: 91,
    bestTcpLatency: 56,
    isReachable: true,
    explanation: "响应迅速（延迟 56ms，抖动 5ms），推荐作为备用亚太节点",
    protocol: "TCP",
    port: 443,
    lastMeasuredAt: Date.now() - 1000 * 60 * 5,
  },
  {
    nodeId: "node-nl-free-01",
    serverName: "NL-FREE#101",
    country: "荷兰",
    city: "Amsterdam",
    overallScore: 82,
    webScore: 84,
    videoScore: 80,
    stabilityScore: 86,
    bestTcpLatency: 178,
    isReachable: true,
    explanation: "延迟中等（延迟 178ms，抖动 8ms），欧洲骨干网络，隐私保护性高",
    protocol: "UDP",
    port: 1194,
    lastMeasuredAt: Date.now() - 1000 * 60 * 8,
  },
  {
    nodeId: "node-us-free-01",
    serverName: "US-FREE#21",
    country: "美国",
    city: "Los Angeles",
    overallScore: 78,
    webScore: 81,
    videoScore: 76,
    stabilityScore: 82,
    bestTcpLatency: 165,
    isReachable: true,
    explanation: "美西直连节点（延迟 165ms，抖动 12ms），线路负载中等",
    protocol: "UDP",
    port: 51820,
    lastMeasuredAt: Date.now() - 1000 * 60 * 12,
  },
  {
    nodeId: "node-us-free-02",
    serverName: "US-FREE#45",
    country: "美国",
    city: "New York",
    overallScore: 71,
    webScore: 73,
    videoScore: 69,
    stabilityScore: 75,
    bestTcpLatency: 220,
    isReachable: true,
    explanation: "延迟较高（延迟 220ms），适合普通浏览及跨洋下载",
    protocol: "TCP",
    port: 8443,
    lastMeasuredAt: Date.now() - 1000 * 60 * 15,
  },
  {
    nodeId: "node-ro-free-01",
    serverName: "RO-FREE#04",
    country: "罗马尼亚",
    city: "Bucharest",
    overallScore: 76,
    webScore: 78,
    videoScore: 74,
    stabilityScore: 80,
    bestTcpLatency: 195,
    isReachable: true,
    explanation: "东欧节点（延迟 195ms），隐私法律宽松，适合敏感操作",
    protocol: "UDP",
    port: 5060,
    lastMeasuredAt: Date.now() - 1000 * 60 * 20,
  },
  {
    nodeId: "node-pl-free-01",
    serverName: "PL-FREE#12",
    country: "波兰",
    city: "Warsaw",
    overallScore: 65,
    webScore: 67,
    videoScore: 62,
    stabilityScore: 70,
    bestTcpLatency: 240,
    isReachable: true,
    explanation: "延迟偏高（延迟 240ms），当前节点负载较重",
    protocol: "TCP",
    port: 443,
    lastMeasuredAt: Date.now() - 1000 * 60 * 30,
  }
];

let vpnState = {
  isConnected: false,
  code: "DISCONNECTED",
  state: "未连接",
  connectedNodeId: null as string | null,
  runtimeDisplayName: "OpenVPN 2.7.5 (x86_64-w64-mingw32)",
  runtimeReady: true,
  driverReady: true,
  mode: "split" as "global" | "split",
  isRoutingRunning: false,
  hasCredentials: true,
  snapshot: {
    direct_ip: "114.248.162.88",
    vpn_ip: undefined as string | undefined,
    direct_dns: ["223.5.5.5", "119.29.29.29"],
    vpn_dns: undefined as string[] | undefined,
    direct_interface: "以太网 (Intel Ethernet Connection)",
    vpn_interface: "OpenSight-TUN (Wintun Virtual Adapter)"
  }
};

let routingRules = [
  {
    ruleId: "rule-1",
    appName: "Google Chrome",
    executablePath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    action: "VPN" as const,
    isEnabled: true
  },
  {
    ruleId: "rule-2",
    appName: "Telegram Desktop",
    executablePath: "C:\\Users\\User\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe",
    action: "VPN" as const,
    isEnabled: true
  },
  {
    ruleId: "rule-3",
    appName: "Steam",
    executablePath: "C:\\Program Files (x86)\\Steam\\steam.exe",
    action: "DIRECT" as const,
    isEnabled: true
  },
  {
    ruleId: "rule-4",
    appName: "WeChat 微信",
    executablePath: "C:\\Program Files\\Tencent\\WeChat\\WeChat.exe",
    action: "DIRECT" as const,
    isEnabled: true
  }
];

let installedApps = [
  {
    appName: "Google Chrome",
    executablePath: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    publisher: "Google LLC",
    version: "125.0.6422.113"
  },
  {
    appName: "Microsoft Edge",
    executablePath: "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
    publisher: "Microsoft Corporation",
    version: "125.0.2535.67"
  },
  {
    appName: "Telegram Desktop",
    executablePath: "C:\\Users\\User\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe",
    publisher: "Telegram FZ-LLC",
    version: "5.1.4"
  },
  {
    appName: "Discord",
    executablePath: "C:\\Users\\User\\AppData\\Local\\Discord\\app-1.0.9145\\Discord.exe",
    publisher: "Discord Inc.",
    version: "1.0.9145"
  },
  {
    appName: "Spotify",
    executablePath: "C:\\Users\\User\\AppData\\Roaming\\Spotify\\Spotify.exe",
    publisher: "Spotify AB",
    version: "1.2.37"
  },
  {
    appName: "Visual Studio Code",
    executablePath: "C:\\Users\\User\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe",
    publisher: "Microsoft Corporation",
    version: "1.90.0"
  },
  {
    appName: "Steam",
    executablePath: "C:\\Program Files (x86)\\Steam\\steam.exe",
    publisher: "Valve Corp.",
    version: "2.10.91"
  },
  {
    appName: "WeChat 微信",
    executablePath: "C:\\Program Files\\Tencent\\WeChat\\WeChat.exe",
    publisher: "Tencent Inc.",
    version: "3.9.10"
  }
];

let systemLogs = [
  "[SYSTEM] OpenSight 3.1 核心服务就绪，PID 14280",
  "[SEC] 凭据存储初始化完毕 (Windows DPAPI 保护)",
  "[NET] 检测到本地网络接口: 以太网 (Intel I219-V, MTU 1500)",
  "[DRIVER] Wintun 驱动已加载 (OpenSight-TUN / wintun.sys v0.14.1)",
  "[PROBE] 节点探测引擎已准备就绪，工作线程池大小: 6",
  "[INFO] 成功载入 7 个 ProtonVPN 预置免费配置",
  "[LEAK_GUARD] IPv6 与 DNS 泄漏防火墙拦截规则就绪"
];

let repairProgress = 0;
let isRepairing = false;

// Broadcast to all WebSocket clients
function broadcast(event: string, data: any) {
  const payload = JSON.stringify({ event, data });
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(payload);
    }
  });
}

// WebSocket Connection handler
wss.on('connection', (ws) => {
  ws.send(JSON.stringify({
    event: 'vpn_state_change',
    data: {
      code: vpnState.code,
      message: vpnState.state,
      connectedNodeId: vpnState.connectedNodeId
    }
  }));
});

// Periodic traffic generator when connected
let lastBytesIn = 1024 * 1024 * 142;
let lastBytesOut = 1024 * 1024 * 38;
let currentUploadSpeed = 0;
let currentDownloadSpeed = 0;

setInterval(() => {
  if (vpnState.isConnected) {
    currentUploadSpeed = Math.floor(Math.random() * 450000) + 120000;
    currentDownloadSpeed = Math.floor(Math.random() * 4500000) + 1800000;
    lastBytesIn += currentDownloadSpeed;
    lastBytesOut += currentUploadSpeed;
    broadcast("traffic_data", {
      uploadSpeedBps: currentUploadSpeed,
      downloadSpeedBps: currentDownloadSpeed,
      bytesIn: lastBytesIn,
      bytesOut: lastBytesOut
    });
  } else {
    currentUploadSpeed = 0;
    currentDownloadSpeed = 0;
  }
}, 1000);

// Core API endpoints
app.get('/api/health', (req, res) => {
  res.json({
    status: "ok",
    app: "OpenSight",
    version: "3.1.0"
  });
});

let mockRecentNodes: string[] = ["node-jp-free-01", "node-jp-free-02"];

app.get('/api/nodes', (req, res) => {
  res.json(mockNodes);
});

app.get('/api/nodes/recent', (req, res) => {
  res.json(mockRecentNodes);
});

app.post('/api/nodes/recent', (req, res) => {
  const { node_ids } = req.body;
  if (Array.isArray(node_ids)) {
    mockRecentNodes = node_ids.map(String).slice(0, 20);
  }
  res.json({ ok: true, count: mockRecentNodes.length });
});

app.post('/api/nodes/import', (req, res) => {
  systemLogs.push(`[IMPORT] 用户扫描配置目录，已成功解析 7 个配置文件`);
  res.json({ imported: 7, errors: 0 });
});

app.post('/api/nodes/open-folder', (req, res) => {
  systemLogs.push(`[UI] 打开本地配置文件夹目录`);
  res.json({ ok: true, success: true });
});

let probeTimer: NodeJS.Timeout | null = null;

function runMockProbe() {
  if (probeTimer) clearInterval(probeTimer);
  let completed = 0;
  const total = mockNodes.length;

  probeTimer = setInterval(() => {
    completed++;
    const node = mockNodes[completed - 1];
    const percentage = Math.round((completed / total) * 100);

    if (node) {
      const jitter = Math.floor(Math.random() * 6) - 3;
      if (node.bestTcpLatency) {
        node.bestTcpLatency = Math.max(25, node.bestTcpLatency + jitter);
      }
      node.lastMeasuredAt = Date.now();
    }

    broadcast("probe_progress", {
      total,
      completed,
      percentage,
      currentNode: node ? `${node.serverName} (${node.city})` : "完成",
      stage: "TCP RTT 抖动退避测速"
    });

    if (completed >= total) {
      if (probeTimer) clearInterval(probeTimer);
      probeTimer = null;
      broadcast("probe_finished", { total, success: total, stopped: false });
      systemLogs.push(`[PROBE] 全量测速完成，所有 ${total} 个节点均通过健康检测`);
    }
  }, 400);
}

app.post('/api/probe/start', (req, res) => {
  runMockProbe();
  res.json({ status: "started" });
});

app.post('/api/probe/stop', (req, res) => {
  if (probeTimer) {
    clearInterval(probeTimer);
    probeTimer = null;
    broadcast("probe_finished", { stopped: true });
    systemLogs.push(`[PROBE] 测速已由用户手动停止`);
  }
  res.json({ status: "stopping" });
});

app.post('/api/nodes/probe', (req, res) => {
  runMockProbe();
  res.json({ status: "probing_started" });
});

app.get('/api/vpn/status', (req, res) => {
  res.json(vpnState);
});

app.get('/api/vpn/traffic', (req, res) => {
  res.json({
    uploadSpeedBps: currentUploadSpeed,
    downloadSpeedBps: currentDownloadSpeed,
    bytesIn: lastBytesIn,
    bytesOut: lastBytesOut
  });
});

app.post('/api/vpn/connect', (req, res) => {
  const { nodeId, node_id, mode } = req.body;
  const targetId = nodeId || node_id;
  const targetNode = mockNodes.find(n => n.nodeId === targetId) || mockNodes[0];

  vpnState.connectedNodeId = targetNode.nodeId;
  vpnState.mode = mode || "split";
  vpnState.state = "正在协商加密握手...";
  vpnState.code = "CONNECTING";
  
  broadcast("vpn_state_change", {
    code: "CONNECTING",
    message: "正在协商加密握手...",
    connectedNodeId: targetNode.nodeId
  });

  setTimeout(() => {
    vpnState.isConnected = true;
    vpnState.code = "CONNECTED";
    vpnState.state = `已连接至 ${targetNode.serverName} (${vpnState.mode === "split" ? "应用分流模式" : "全局加速模式"})`;
    vpnState.isRoutingRunning = vpnState.mode === "split";
    vpnState.snapshot.vpn_ip = `185.159.157.${Math.floor(Math.random() * 150) + 10}`;
    vpnState.snapshot.vpn_dns = ["10.2.0.1"];

    broadcast("vpn_state_change", {
      code: "CONNECTED",
      message: vpnState.state,
      connectedNodeId: targetNode.nodeId
    });

    systemLogs.push(`[VPN] 成功建立 OpenVPN 隧道 -> ${targetNode.serverName} [${targetNode.country}] [${vpnState.mode}]`);
    if (vpnState.mode === "split") {
      systemLogs.push(`[SING-BOX] sing-box 进程启动 PID 16792, TUN 分流策略规则已生效 (${routingRules.filter(r => r.isEnabled).length} 条规则)`);
    }
  }, 1200);

  res.json({ success: true, status: "connecting", message: "Connecting" });
});

app.post('/api/vpn/disconnect', (req, res) => {
  vpnState.isConnected = false;
  vpnState.code = "DISCONNECTED";
  vpnState.state = "未连接";
  vpnState.connectedNodeId = null;
  vpnState.isRoutingRunning = false;
  vpnState.snapshot.vpn_ip = undefined;
  vpnState.snapshot.vpn_dns = undefined;

  broadcast("vpn_state_change", {
    code: "DISCONNECTED",
    message: "未连接",
    connectedNodeId: null
  });

  systemLogs.push(`[VPN] OpenVPN 隧道已安全关闭，释放虚拟适配器与路由表`);
  res.json({ success: true, status: "disconnecting", message: "Disconnected" });
});

// Credentials endpoints (support both /api/credentials and /api/vpn/credentials)
const handleGetCreds = (req: express.Request, res: express.Response) => {
  res.json({
    hasCredentials: mockCredentials.hasCredentials,
    username: mockCredentials.username
  });
};

const handleSaveCreds = (req: express.Request, res: express.Response) => {
  const { username, password } = req.body;
  mockCredentials.hasCredentials = true;
  mockCredentials.username = username || "";
  mockCredentials.password = password || "";
  vpnState.hasCredentials = true;
  systemLogs.push(`[AUTH] VPN 账户凭据已更新并加密存储 (Windows DPAPI)`);
  res.json({ ok: true, success: true });
};

const handleClearCreds = (req: express.Request, res: express.Response) => {
  mockCredentials.hasCredentials = false;
  mockCredentials.username = "";
  mockCredentials.password = "";
  vpnState.hasCredentials = false;
  systemLogs.push(`[AUTH] 凭据已从安全存储区清除`);
  res.json({ ok: true, success: true });
};

app.get('/api/credentials', handleGetCreds);
app.post('/api/credentials', handleSaveCreds);
app.delete('/api/credentials', handleClearCreds);

app.get('/api/vpn/credentials', handleGetCreds);
app.post('/api/vpn/credentials', handleSaveCreds);
app.delete('/api/vpn/credentials', handleClearCreds);

// Routing rules endpoints
app.get('/api/routing/rules', (req, res) => {
  res.json(routingRules);
});

app.get('/api/routing/installed-apps', (req, res) => {
  res.json(installedApps);
});
app.get('/api/routing/apps', (req, res) => {
  res.json(installedApps);
});

app.post('/api/routing/rule', (req, res) => {
  const { executable_path, app_name, action, enabled } = req.body;
  const path = executable_path;
  const name = app_name;
  const existingIdx = routingRules.findIndex(r => r.executablePath.toLowerCase() === (path || '').toLowerCase());
  
  if (existingIdx >= 0) {
    routingRules[existingIdx] = {
      ...routingRules[existingIdx],
      appName: name || routingRules[existingIdx].appName,
      action: action || routingRules[existingIdx].action,
      isEnabled: enabled !== undefined ? enabled : routingRules[existingIdx].isEnabled
    };
  } else {
    routingRules.push({
      ruleId: `r_${Date.now()}`,
      appName: name || "未知应用",
      executablePath: path || "",
      action: action || "VPN",
      isEnabled: enabled !== undefined ? enabled : true
    });
  }
  systemLogs.push(`[ROUTING] 更新分流规则: ${name || path} -> ${action} (${enabled ? '启用' : '禁用'})`);
  res.json({ ok: true });
});

app.post('/api/routing/rules', (req, res) => {
  const rule = req.body;
  const existingIdx = routingRules.findIndex(r => r.ruleId === rule.ruleId || r.executablePath === rule.executablePath);
  if (existingIdx >= 0) {
    routingRules[existingIdx] = rule;
  } else {
    routingRules.push({ ...rule, ruleId: rule.ruleId || `rule-${Date.now()}` });
  }
  systemLogs.push(`[ROUTING] 更新分流规则: ${rule.appName} -> ${rule.action}`);
  res.json({ ok: true, success: true, rules: routingRules });
});

app.delete('/api/routing/rule', (req, res) => {
  const executablePath = (req.query.executable_path as string) || req.body?.executable_path;
  if (executablePath) {
    routingRules = routingRules.filter(r => r.executablePath.toLowerCase() !== executablePath.toLowerCase());
    systemLogs.push(`[ROUTING] 移除分流规则: ${executablePath}`);
  }
  res.json({ ok: true });
});

app.delete('/api/routing/rules/:id', (req, res) => {
  routingRules = routingRules.filter(r => r.ruleId !== req.params.id);
  systemLogs.push(`[ROUTING] 删除分流规则 ID: ${req.params.id}`);
  res.json({ ok: true, success: true, rules: routingRules });
});

app.post('/api/routing/start', (req, res) => {
  vpnState.isRoutingRunning = true;
  systemLogs.push(`[ROUTING] sing-box 分流进程启动 (TUN 虚拟网卡已接管应用流量)`);
  res.json({ ok: true, state: "RUNNING" });
});

app.post('/api/routing/stop', (req, res) => {
  vpnState.isRoutingRunning = false;
  systemLogs.push(`[ROUTING] sing-box 分流进程停止`);
  res.json({ ok: true, state: "STOPPED" });
});

app.post('/api/routing/toggle', (req, res) => {
  vpnState.isRoutingRunning = !vpnState.isRoutingRunning;
  systemLogs.push(`[ROUTING] 切换 sing-box 进程状态: ${vpnState.isRoutingRunning ? "启动" : "停止"}`);
  res.json({ isRunning: vpnState.isRoutingRunning });
});

// Logs endpoints
app.get('/api/logs', (req, res) => {
  res.json({ logs: systemLogs.slice(-200) });
});

app.delete('/api/logs', (req, res) => {
  systemLogs = [];
  res.json({ ok: true });
});

app.get('/api/system/logs', (req, res) => {
  res.json(systemLogs);
});

// Repair OpenVPN endpoints
const startRepair = () => {
  if (isRepairing) return false;
  isRepairing = true;
  repairProgress = 5;
  systemLogs.push(`[REPAIR] 启动 Windows 虚拟网卡与 OpenVPN 驱动静默修复流程...`);

  const steps = [
    { p: 15, msg: "正在终止冲突进程与释放旧网络适配器..." },
    { p: 30, msg: "正在校验本地预置 OpenVPN-2.7.5 MSI 安装包哈希..." },
    { p: 60, msg: "正在调用 msiexec 静默安装 TAP-Windows6 与 Wintun 驱动..." },
    { p: 82, msg: "正在配置 OpenSight-TUN 虚拟网络适配器与防火墙策略..." },
    { p: 100, msg: "驱动修复成功，虚拟网卡工作正常！" }
  ];

  let stepIdx = 0;
  const interval = setInterval(() => {
    if (stepIdx < steps.length) {
      repairProgress = steps[stepIdx].p;
      systemLogs.push(`[REPAIR] (${repairProgress}%) ${steps[stepIdx].msg}`);
      stepIdx++;
    } else {
      clearInterval(interval);
      isRepairing = false;
      vpnState.driverReady = true;
    }
  }, 500);

  return true;
};

app.post('/api/openvpn/install', (req, res) => {
  if (vpnState.isConnected || vpnState.isRoutingRunning) {
    return res.json({ error: "请先断开 VPN 并停止应用分流，再修复驱动" });
  }
  startRepair();
  res.json({ ok: true });
});

app.get('/api/openvpn/install-status', (req, res) => {
  res.json({
    state: isRepairing ? "running" : (repairProgress >= 100 ? "completed" : "idle"),
    percentage: repairProgress,
    message: isRepairing ? `驱动修复中 (${repairProgress}%)` : (repairProgress >= 100 ? "官方驱动修复完成，网卡就绪" : "就绪")
  });
});

app.post('/api/system/openvpn/install', (req, res) => {
  if (isRepairing) {
    return res.json({ status: "already_running", progress: repairProgress });
  }
  startRepair();
  res.json({ status: "started", progress: 5 });
});

app.get('/api/system/openvpn/install/status', (req, res) => {
  res.json({
    status: isRepairing ? "running" : (repairProgress >= 100 ? "completed" : "idle"),
    progress: repairProgress,
    message: isRepairing ? `驱动修复中 (${repairProgress}%)` : (repairProgress >= 100 ? "修复完成" : "空闲")
  });
});

app.get('/api/system/openvpn/status', (req, res) => {
  res.json({
    installed: true,
    driverReady: vpnState.driverReady,
    version: "OpenVPN 2.7.5"
  });
});

app.post('/api/system/uninstall', (req, res) => {
  systemLogs.push(`[SYSTEM] 接收到卸载与彻底清理指令，准备清理虚拟网卡与便携目录`);
  res.json({ ok: true });
});

app.get('/api/system/public-ip', (req, res) => {
  if (vpnState.isConnected) {
    res.json({
      ip: vpnState.snapshot.vpn_ip || "185.159.157.42",
      source: "icanhazip.com (境外隐私节点)",
      country: "日本 / Tokyo (Proton AG)",
      is_vpn: true
    });
  } else {
    res.json({
      ip: vpnState.snapshot.direct_ip || "114.248.162.88",
      source: "myip.ipip.net (境内基准源)",
      country: "中国 / 北京 (中国联通)",
      is_vpn: false
    });
  }
});

// Setup Vite or Static File Serving
async function startServer() {
  const isProduction = process.env.NODE_ENV === 'production';
  const distWebDir = path.resolve(__dirname, 'dist-web');

  if (isProduction && fs.existsSync(distWebDir)) {
    app.use(express.static(distWebDir));
    app.get('*', (req, res, next) => {
      if (req.path.startsWith('/api') || req.path.startsWith('/ws')) {
        return next();
      }
      res.sendFile(path.join(distWebDir, 'index.html'));
    });
  } else {
    // In dev mode, use Vite dev middleware
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
      root: path.resolve(__dirname, 'web')
    });
    app.use(vite.middlewares);
  }

  const PORT = 3000;
  server.listen(PORT, '0.0.0.0', () => {
    console.log(`OpenSight 3.1 server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch(err => {
  console.error("Failed to start OpenSight server:", err);
  process.exit(1);
});
