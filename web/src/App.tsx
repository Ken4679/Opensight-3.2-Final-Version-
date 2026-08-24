import React, { useEffect, useMemo, useState, useCallback } from "react";

import { invoke } from "@tauri-apps/api/core";

import { ApiClient } from "./utils/api";

import { toast } from "./utils/toast";

import { ToastContainer } from "./components/ToastContainer";

import { Sidebar } from "./components/Sidebar";

import { TopBar } from "./components/TopBar";

import { ProbeProgress } from "./components/ProbeProgress";

import { NodeList } from "./components/NodeList";

import { RoutingPanel } from "./components/RoutingPanel";

import { LogViewer } from "./components/LogViewer";

import { SettingsPanel } from "./components/SettingsPanel";

import { CredentialModal } from "./components/CredentialModal";

import { NetInfoModal } from "./components/NetInfoModal";
import { ConnectModal } from "./components/ConnectModal";

import { InstalledApp, NodeItem, ProbeProgressData, RoutingAction, RoutingRule, TrafficData, VPNStatus } from "./types";



export default function App() {

  const [port, setPort] = useState<number | null>(null);

  const [authToken, setAuthToken] = useState<string>("");

  const [ready, setReady] = useState(false);

  const [isDark, setIsDark] = useState(true);

  const [activeTab, setActiveTab] = useState("nodes");



  // 数据状态

  const [nodes, setNodes] = useState<NodeItem[]>([]);

  const [nodesLoading, setNodesLoading] = useState(true);

  const [isProbing, setIsProbing] = useState(false);

  const [probeProgress, setProbeProgress] = useState<ProbeProgressData>({

    total: 0,

    completed: 0,

    percentage: 0,

    currentNode: "",

    stage: "",

  });



  const [vpnStatus, setVpnStatus] = useState<VPNStatus>({

    isConnected: false,

    state: "未连接",

    connectedNodeId: null,

    isRoutingRunning: false,

    hasCredentials: false,

  });



  const [traffic, setTraffic] = useState<TrafficData>({ uploadSpeedBps: 0, downloadSpeedBps: 0 });

  const [logs, setLogs] = useState<string[]>([]);

  const [routingRules, setRoutingRules] = useState<RoutingRule[]>([]);

  const [installedApps, setInstalledApps] = useState<InstalledApp[]>([]);



  // 弹窗状态

  const [showCredModal, setShowCredModal] = useState(false);

  const [showNetModal, setShowNetModal] = useState(false);

  const [defaultUsername, setDefaultUsername] = useState("");
  const [recentNodeIds, setRecentNodeIds] = useState<string[]>(() => { try { return JSON.parse(localStorage.getItem("opensight.recentNodes.v1") || "[]"); } catch { return []; } });
  const [connectNodeId, setConnectNodeId] = useState<string | null>(null);
  const [showConnectModal, setShowConnectModal] = useState(false);
  const [repairProgress, setRepairProgress] = useState(0);



  // 忙碌遮罩

  const [isBusy, setIsBusy] = useState(false);

  const [busyText, setBusyText] = useState("");



  const api = useMemo(() => (port ? new ApiClient(port, authToken) : null), [port, authToken]);



  useEffect(() => {

    document.documentElement.classList.toggle("dark", isDark);

  }, [isDark]);



  // 初始化与 IPC 通信绑定

  useEffect(() => {

    let ws: WebSocket | undefined;



    async function init() {
      try {
        let p = 3000;
        let token = "opensight-token";
        try {
          p = await invoke<number>("get_backend_port");
          token = await invoke<string>("get_auth_token");
        } catch {
          p = (typeof window !== "undefined" && window.location.port) ? parseInt(window.location.port) : 3000;
          token = "opensight-web-token";
        }

        setPort(p);
        setAuthToken(token);

        const client = new ApiClient(p, token);
        for (let i = 0; i < 30; i++) {
          try {
            const health = await client.health();
            if (health.status === "ok") break;
          } catch {}
          await new Promise((r) => setTimeout(r, 100));
        }
        setReady(true);

        const [initialNodes, initialVpn, initialCreds, initialRecent] = await Promise.all([
          client.getNodes().catch(() => []),
          client.getVpnStatus().catch(() => ({
            isConnected: false,
            state: "未连接",
            connectedNodeId: null,
            isRoutingRunning: false,
            hasCredentials: false,
          })),
          client.getCredentials().catch(() => ({ hasCredentials: false, username: "" })),
          client.getRecentNodes().catch(() => []),
        ]);

        setNodes(initialNodes);
        setNodesLoading(false);
        setVpnStatus(initialVpn);
        if (initialCreds.username) setDefaultUsername(initialCreds.username);
        if (Array.isArray(initialRecent) && initialRecent.length > 0) {
          setRecentNodeIds(initialRecent);
          try {
            localStorage.setItem("opensight.recentNodes.v1", JSON.stringify(initialRecent));
          } catch {}
        }

        const wsProto = (typeof window !== "undefined" && window.location.protocol === "https:") ? "wss:" : "ws:";
        const wsHost = (typeof window !== "undefined" && window.location.hostname !== "127.0.0.1" && window.location.hostname !== "localhost")
          ? window.location.host
          : `127.0.0.1:${p}`;

        ws = new WebSocket(`${wsProto}//${wsHost}/ws?token=${encodeURIComponent(token)}`);

        ws.onmessage = (e) => {

          try {

            const msg = JSON.parse(e.data);

            if (msg.event === "probe_progress") {

              setIsProbing(true);

              setProbeProgress(msg.data);

            } else if (msg.event === "probe_finished") {

              setIsProbing(false);

              client.getNodes().then(setNodes);

              toast.success("测速完成", "所有节点评分与延迟已更新。");

            } else if (msg.event === "vpn_state_change") {

              setVpnStatus((prev) => ({

                ...prev,

                code: msg.data.code,

                state: msg.data.message,

                isConnected: msg.data.code === "CONNECTED",

              }));

              client.getVpnStatus().then(setVpnStatus);

            }

          } catch {}

        };

      } catch (err) {

        toast.error("初始化错误", "无法与 OpenSight 核心服务建立 IPC 连接。");

      }

    }



    void init();

    return () => ws?.close();

  }, []);



  // 流量轮询

  useEffect(() => {

    if (!api || !vpnStatus.isConnected) {

      setTraffic({ uploadSpeedBps: 0, downloadSpeedBps: 0 });

      return;

    }

    const timer = setInterval(async () => {

      try {

        const t = await api.getTraffic();

        setTraffic(t);

      } catch {}

    }, 1000);

    return () => clearInterval(timer);

  }, [api, vpnStatus.isConnected]);



  // Tab 切换加载对应数据

  useEffect(() => {

    if (!api) return;

    if (activeTab === "routing") {

      api.getRoutingRules().then(setRoutingRules);

      api.getInstalledApps().then(setInstalledApps);

    } else if (activeTab === "logs") {

      api.getLogs().then(setLogs);

    }

  }, [activeTab, api]);



  // 节点操作
  const rememberRecentNode = useCallback((nodeId: string) => {
    setRecentNodeIds((prev) => {
      const next = [nodeId, ...prev.filter((id) => id !== nodeId)].slice(0, 8);
      try {
        localStorage.setItem("opensight.recentNodes.v1", JSON.stringify(next));
      } catch {}
      if (api) {
        api.setRecentNodes(next).catch(() => {});
      }
      return next;
    });
  }, [api]);
  const handleConnectNode = useCallback(async (nodeId: string) => {
    if (!api) return;
    if (!vpnStatus.hasCredentials) { setShowCredModal(true); return; }
    if (vpnStatus.isConnected && vpnStatus.connectedNodeId === nodeId) return;
    setConnectNodeId(nodeId); setShowConnectModal(true);
  }, [api, vpnStatus.hasCredentials, vpnStatus.isConnected, vpnStatus.connectedNodeId]);
  const confirmConnect = useCallback(async (mode: "global" | "split") => {
    if (!api || !connectNodeId) return;
    setShowConnectModal(false);
    if (vpnStatus.isConnected && vpnStatus.connectedNodeId !== connectNodeId) {
      if (vpnStatus.isRoutingRunning) await api.stopRouting();
      await api.disconnectVPN();
      for (let i=0;i<40;i+=1){ await new Promise(r=>setTimeout(r,250)); try{const status=await api.getVpnStatus(); if(!status.isConnected && status.state!=="DISCONNECTING") break;}catch{} }
    }
    const res=await api.connectVPN(connectNodeId,mode);
    if(res.error){toast.error("连接失败",res.error);return;}
    rememberRecentNode(connectNodeId);
    toast.info(mode === "split" ? "正在连接（应用分流）" : "正在连接（全局模式）","正在建立安全连接，请稍候。");
  }, [api, connectNodeId, rememberRecentNode, vpnStatus.isConnected, vpnStatus.connectedNodeId, vpnStatus.isRoutingRunning]);



  const handleDisconnectVPN = useCallback(async () => {

    if (!api) return;

    if (vpnStatus.isRoutingRunning) await api.stopRouting();
    await api.disconnectVPN();

    toast.info("断开连接", "正在安全关闭 VPN 隧道与恢复网络。");

  }, [api]);



  // 分流操作（增加分流运行时锁定拦截）

  const handleAddRoutingRule = useCallback(async (app: InstalledApp, action: RoutingAction): Promise<boolean> => {

    if (!api) return false;

    if (vpnStatus.isRoutingRunning) {

      toast.warning("操作受限", "分流引擎运行中已锁定规则，请先点击「停止分流」后再添加。");

      return false;

    }



    const optimisticRule: RoutingRule = {

      ruleId: "temp_" + Date.now(),

      appName: app.appName,

      executablePath: app.executablePath,

      action,

      isEnabled: true,

    };

    setRoutingRules((prev) => [...prev, optimisticRule]);



    const res = await api.setRoutingRule(app.executablePath, app.appName, action, true);

    if (res.error || !res.ok) {

      setRoutingRules((prev) => prev.filter((r) => r.executablePath !== app.executablePath));

      toast.error("添加规则失败", res.error || "无法保存分流规则");

      return false;

    }



    toast.success("规则已添加", `${app.appName} 已指定为 ${action === "VPN" ? "走 VPN" : "直连"}`);

    api.getRoutingRules().then(setRoutingRules);

    return true;

  }, [api, vpnStatus.isRoutingRunning]);



  const handleToggleRule = useCallback(async (rule: RoutingRule): Promise<boolean> => {

    if (!api) return false;

    if (vpnStatus.isRoutingRunning) {

      toast.warning("操作受限", "分流引擎运行中已锁定规则，请先点击「停止分流」后再切换状态。");

      return false;

    }



    const targetState = !rule.isEnabled;

    setRoutingRules((prev) =>

      prev.map((r) => (r.executablePath === rule.executablePath ? { ...r, isEnabled: targetState } : r))

    );



    const res = await api.setRoutingRule(rule.executablePath, rule.appName, rule.action, targetState);

    if (res.error || !res.ok) {

      setRoutingRules((prev) =>

        prev.map((r) => (r.executablePath === rule.executablePath ? { ...r, isEnabled: !targetState } : r))

      );

      toast.error("更新规则失败", res.error);

      return false;

    }

    return true;

  }, [api, vpnStatus.isRoutingRunning]);



  const handleDeleteRule = useCallback(async (rule: RoutingRule): Promise<boolean> => {

    if (!api) return false;

    if (vpnStatus.isRoutingRunning) {

      toast.warning("操作受限", "分流引擎运行中已锁定规则，请先点击「停止分流」后再删除。");

      return false;

    }



    setRoutingRules((prev) => prev.filter((r) => r.executablePath !== rule.executablePath));

    await api.deleteRoutingRule(rule.executablePath);

    toast.info("规则已移除", rule.appName);

    return true;

  }, [api, vpnStatus.isRoutingRunning]);



  const handleToggleRoutingBackend = useCallback(async () => {

    if (!api) return;

    if (vpnStatus.isRoutingRunning) {

      await api.stopRouting();

      toast.info("分流已停止", "应用分流已解除，配置规则已解锁。");

    } else {

      const res = await api.startRouting();

      if (res.error) {

        toast.error("启动分流失败", res.error);

      } else {

        toast.success("应用分流已就绪", "指定应用流量已由 TUN 虚拟网卡隔离接管。");

      }

    }

    api.getVpnStatus().then(setVpnStatus);

  }, [api, vpnStatus.isRoutingRunning]);



  // 凭据保存

  const handleSaveCreds = useCallback(async (u: string, p: string) => {

    if (!api) return;

    await api.saveCredentials(u, p);

    setVpnStatus((prev) => ({ ...prev, hasCredentials: true }));

    setShowCredModal(false);

    toast.success("凭据已加密保存", "已通过 Windows DPAPI 硬件加密隔离。");

  }, [api]);



  const handleClearCreds = useCallback(async () => {

    if (!api) return;

    await api.clearCredentials();

    setVpnStatus((prev) => ({ ...prev, hasCredentials: false }));

    setShowCredModal(false);

    toast.info("凭据已清除", "本地已无保存的 VPN 账号。");

  }, [api]);



  if (!ready) {

    return (

      <div className={`h-screen w-screen flex flex-col items-center justify-center ${isDark ? "dark bg-[#0d1117] text-[#e6edf3]" : "bg-white text-[#1f2328]"}`}>

        <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mb-3" />

        <p className="text-xs text-[#656d76] dark:text-[#8b949e]">正在建立本地安全通信与隔离环境...</p>

      </div>

    );

  }



  return (

    <div className={`flex h-screen w-screen overflow-hidden select-none ${isDark ? "dark bg-[#0d1117] text-[#e6edf3]" : "bg-[#f6f8fa] text-[#1f2328]"}`}>

      <ToastContainer />



      <Sidebar

        activeTab={activeTab}

        setActiveTab={setActiveTab}

        isDark={isDark}

        setIsDark={setIsDark}

        vpnStatus={vpnStatus}

        onDisconnect={handleDisconnectVPN}

      />



      <main className="flex-1 flex flex-col min-w-0 overflow-hidden bg-[#f6f8fa] dark:bg-[#0d1117] transition-colors">

        <TopBar

          activeTab={activeTab}

          vpnStatus={vpnStatus}

          traffic={traffic}

          isProbing={isProbing}

          probePercentage={probeProgress.percentage}

          hasSavedCreds={vpnStatus.hasCredentials}

          onOpenNetModal={() => {

            api?.getVpnStatus().then(setVpnStatus);

            setShowNetModal(true);

          }}

          onOpenCredModal={() => setShowCredModal(true)}

          onOpenFolder={() => api?.openProfilesFolder()}

          onImportProfiles={async () => {

            if (!api) return;

            try {

              const res = await api.importProfiles();

              toast.success("配置导入完成", `成功导入 ${res.imported} 个节点，异常 ${res.errors} 个`);

              api.getNodes().then(setNodes);

            } catch (err: any) {

              toast.error("导入失败", err.message);

            }

          }}

          onStartProbing={async () => {

            await api?.startProbing();

            setIsProbing(true);

          }}

          onStopProbing={async () => {

            await api?.stopProbing();

            setIsProbing(false);

          }}

        />



        <ProbeProgress isProbing={isProbing} progress={probeProgress} />



        <div className="flex-1 overflow-y-auto p-5">

          {activeTab === "nodes" && (

            <NodeList
              nodes={nodes}
              loading={nodesLoading}
              connectedNodeId={vpnStatus.connectedNodeId}
              isConnected={vpnStatus.isConnected}
              onConnect={handleConnectNode}
              onDisconnect={handleDisconnectVPN}
              recentNodeIds={recentNodeIds}
            />

          )}



          {activeTab === "routing" && (

            <RoutingPanel

              isRoutingRunning={vpnStatus.isRoutingRunning}

              routingRules={routingRules}

              installedApps={installedApps}

              onToggleBackend={handleToggleRoutingBackend}

              onAddRule={handleAddRoutingRule}

              onToggleRule={handleToggleRule}

              onDeleteRule={handleDeleteRule}

              onRefreshApps={() => api?.getInstalledApps().then(setInstalledApps)}

            />

          )}



          {activeTab === "logs" && (

            <LogViewer logs={logs} onClearLogs={() => api?.clearLogs().then(() => setLogs([]))} />

          )}



          {activeTab === "settings" && (
            <SettingsPanel
              isVpnConnected={vpnStatus.isConnected}
              onRepairOpenVPN={async () => {

                if (vpnStatus.isConnected || vpnStatus.isRoutingRunning) { toast.warning("暂时不能修复", "请先断开 VPN 并停止应用分流。"); return; }
                setIsBusy(true); setRepairProgress(5);
                setBusyText("正在准备本地 OpenVPN 驱动修复...");

                const res = await api?.repairOpenVPN();

                if (res?.error) {

                  setIsBusy(false);

                  toast.error("启动安装失败", res.error);

                  return;

                }



                let attempts = 0;

                const pollTimer = setInterval(async () => {

                  attempts++;

                  try {

                    const status = await api?.getOpenVPNInstallStatus();

                    if (status) {

                      if (status.message) setBusyText(status.message);
                      setRepairProgress(Number(status.percentage || 0));

                      if (status.state === "completed") {

                        clearInterval(pollTimer);

                        setIsBusy(false);

                        toast.success("组件就绪", status.message || "OpenVPN 官方驱动已成功配置。");

                        api?.getVpnStatus().then(setVpnStatus);

                      } else if (status.state === "failed") {

                        clearInterval(pollTimer);

                        setIsBusy(false);

                        toast.error("驱动安装失败", status.message || "未能完成 OpenVPN 驱动配置。");

                      }

                    }

                  } catch {}



                  if (attempts > 260) {

                    clearInterval(pollTimer);

                    setIsBusy(false);

                    toast.warning("操作超时", "OpenVPN 驱动安装响应超时，请重试或查看日志。");

                  }

                }, 500);

              }}

              onUninstallAll={async () => {

                if (confirm("确定彻底清理网卡、清除防火墙并卸载 OpenSight 数据吗？\n（此操作将关闭软件并清理驱动）")) {

                  setIsBusy(true);

                  setBusyText("正在彻底清理驱动与便携数据...");

                  await api?.uninstallSystem();

                  setTimeout(() => {

                    setIsBusy(false);

                  }, 5000);

                }

              }}

            />

          )}

        </div>

      </main>



      <CredentialModal

        isOpen={showCredModal}

        hasSavedCreds={vpnStatus.hasCredentials}

        defaultUsername={defaultUsername}

        onClose={() => setShowCredModal(false)}

        onSave={handleSaveCreds}

        onClear={handleClearCreds}

      />



      <ConnectModal isOpen={showConnectModal} nodeName={nodes.find((node) => node.nodeId === connectNodeId)?.serverName || "当前节点"} switching={vpnStatus.isConnected && vpnStatus.connectedNodeId !== connectNodeId} onClose={() => setShowConnectModal(false)} onConfirm={confirmConnect} />

      <NetInfoModal

        isOpen={showNetModal}

        isConnected={vpnStatus.isConnected}

        snapshot={vpnStatus.snapshot}

        onClose={() => setShowNetModal(false)}

      />



      {isBusy && (

        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">

          <div className="p-5 rounded-2xl max-w-xs w-full text-center shadow-2xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22]">

            <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-3" />

            <p className="text-sm font-semibold text-slate-800 dark:text-slate-200">{busyText}</p>
            <div className="mt-4 h-2.5 rounded-full bg-slate-200 dark:bg-slate-800 overflow-hidden"><div className="h-full bg-blue-600 transition-all" style={{ width: `${repairProgress}%` }} /></div>
            <div className="mt-2 flex justify-between text-xs text-[#656d76] dark:text-[#8b949e]"><span>正在处理</span><span>{repairProgress.toFixed(0)}%</span></div>

            <p className="text-[11px] text-[#656d76] dark:text-[#8b949e] mt-1.5">如弹出 Windows 管理员授权，请点击“是”继续</p>

          </div>

        </div>

      )}

    </div>

  );

}
