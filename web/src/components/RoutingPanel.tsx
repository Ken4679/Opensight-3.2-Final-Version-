import React, { useState } from "react";
import { InstalledApp, RoutingAction, RoutingRule } from "../types";
import { Plus, RefreshCw, Trash2, Shuffle, Lock } from "lucide-react";
import { toast } from "../utils/toast";

interface RoutingPanelProps {
  isRoutingRunning: boolean;
  routingRules: RoutingRule[];
  installedApps: InstalledApp[];
  onToggleBackend: () => void;
  onAddRule: (app: InstalledApp, action: RoutingAction) => Promise<boolean>;
  onToggleRule: (rule: RoutingRule) => Promise<boolean>;
  onDeleteRule: (rule: RoutingRule) => Promise<boolean>;
  onRefreshApps: () => void;
}

export const RoutingPanel: React.FC<RoutingPanelProps> = ({
  isRoutingRunning,
  routingRules,
  installedApps,
  onToggleBackend,
  onAddRule,
  onToggleRule,
  onDeleteRule,
  onRefreshApps,
}) => {
  const [selectedExe, setSelectedExe] = useState("");
  const [action, setAction] = useState<RoutingAction>("VPN");
  const [submitting, setSubmitting] = useState(false);

  const handleAdd = async () => {
    if (isRoutingRunning) {
      toast.warning("规则已锁定", "分流引擎正在运行，请先停止分流后再添加规则。");
      return;
    }

    const app = installedApps.find((a) => a.executablePath === selectedExe);
    if (!app) return;

    const exists = routingRules.some(
      (r) => r.executablePath.toLowerCase() === app.executablePath.toLowerCase()
    );
    if (exists) {
      toast.warning("规则已存在", `应用 “${app.appName}” 已配置分流，请直接在列表中修改。`);
      return;
    }

    setSubmitting(true);
    const ok = await onAddRule(app, action);
    setSubmitting(false);
    if (ok) {
      setSelectedExe("");
    }
  };

  return (
    <div className="space-y-4 max-w-4xl">
      {/* 引擎控制卡片 */}
      <div className="p-4 rounded-xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] flex items-center justify-between shadow-sm">
        <div>
          <h3 className="font-semibold text-xs flex items-center gap-1.5">
            <Shuffle className="w-4 h-4 text-blue-500" />
            <span>sing-box TUN 虚拟网卡分流引擎</span>
          </h3>
          <p className="text-[11px] text-[#656d76] dark:text-[#8b949e] mt-0.5">
            运行状态:{" "}
            <b className={isRoutingRunning ? "text-emerald-500 font-semibold" : "text-amber-500 font-semibold"}>
              {isRoutingRunning ? "分流引擎运行中 (接管指定进程流量)" : "未激活 (流量走全局)"}
            </b>
          </p>
        </div>
        <button
          onClick={onToggleBackend}
          className={`px-3.5 py-1.5 rounded-lg text-xs font-semibold text-white shadow transition-all ${
            isRoutingRunning ? "bg-rose-600 hover:bg-rose-700" : "bg-blue-600 hover:bg-blue-700"
          }`}
        >
          {isRoutingRunning ? "停止分流 (解锁规则配置)" : "启动应用分流"}
        </button>
      </div>

      {/* 新增规则卡片（分流运行时锁定置灰） */}
      <div
        className={`p-4 rounded-xl border transition-all shadow-sm space-y-3 ${
          isRoutingRunning
            ? "border-amber-500/30 bg-amber-500/5 dark:bg-amber-950/10"
            : "border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22]"
        }`}
      >
        <div className="flex items-center justify-between">
          <div>
            <h3 className="font-semibold text-xs flex items-center gap-1.5">
              <span>新增应用分流规则</span>
              {isRoutingRunning && (
                <span className="flex items-center gap-1 px-2 py-0.5 rounded bg-amber-500/15 text-amber-600 dark:text-amber-400 text-[10px] font-bold">
                  <Lock className="w-3 h-3" />
                  分流运行中 · 规则已锁定
                </span>
              )}
            </h3>
            <p className="text-[11px] text-[#656d76] dark:text-[#8b949e]">
              {isRoutingRunning
                ? "为了保证网络隧道稳定，分流运行时禁止增删规则。如需修改，请先点击上方「停止分流」。"
                : "选择已安装应用程序，指定其通过 VPN 隧道或本地宽带直连。"}
            </p>
          </div>
          <button
            onClick={onRefreshApps}
            disabled={isRoutingRunning}
            className="p-1.5 rounded-md hover:bg-black/5 dark:hover:bg-[#21262d] text-[#656d76] dark:text-[#8b949e] disabled:opacity-40 disabled:cursor-not-allowed"
            title="重新扫描已安装应用"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-[1fr_auto_auto] gap-2.5">
          <select
            value={selectedExe}
            disabled={isRoutingRunning}
            onChange={(e) => setSelectedExe(e.target.value)}
            className="px-3 py-1.5 rounded-lg border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#0d1117] text-xs disabled:opacity-40 disabled:bg-black/5 dark:disabled:bg-white/5 disabled:cursor-not-allowed"
          >
            <option value="">{isRoutingRunning ? "分流运行中不可添加..." : "选择已安装应用..."}</option>
            {installedApps.map((app) => (
              <option key={app.executablePath} value={app.executablePath}>
                {app.appName} — {app.executablePath}
              </option>
            ))}
          </select>

          <select
            value={action}
            disabled={isRoutingRunning}
            onChange={(e) => setAction(e.target.value as RoutingAction)}
            className="px-3 py-1.5 rounded-lg border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#0d1117] text-xs font-medium disabled:opacity-40 disabled:bg-black/5 dark:disabled:bg-white/5 disabled:cursor-not-allowed"
          >
            <option value="VPN">走 VPN 隧道</option>
            <option value="DIRECT">本地直连</option>
          </select>

          <button
            onClick={handleAdd}
            disabled={!selectedExe || submitting || isRoutingRunning}
            className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-semibold disabled:opacity-40 disabled:cursor-not-allowed flex items-center gap-1 shadow-sm transition-all"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>添加</span>
          </button>
        </div>
      </div>

      {/* 规则列表 */}
      <div className="p-4 rounded-xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] space-y-3 shadow-sm">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-xs">已配置分流规则</h3>
          <span className="text-[11px] text-[#656d76] dark:text-[#8b949e]">共 {routingRules.length} 条</span>
        </div>

        <div className="space-y-2">
          {routingRules.length === 0 ? (
            <div className="py-6 text-center text-xs text-[#656d76] dark:text-[#8b949e]">
              暂无配置规则。默认情况下所有流量均受安全保护。
            </div>
          ) : (
            routingRules.map((rule) => (
              <div
                key={rule.ruleId}
                className="flex items-center justify-between gap-3 rounded-lg border border-[#d0d7de] dark:border-[#30363d] px-3 py-2 bg-[#f6f8fa]/50 dark:bg-[#0d1117]/50"
              >
                <div className="min-w-0">
                  <div className="text-xs font-medium truncate text-slate-800 dark:text-slate-200">
                    {rule.appName}
                  </div>
                  <div className="text-[10px] font-mono text-[#656d76] dark:text-[#8b949e] truncate max-w-md">
                    {rule.executablePath}
                  </div>
                </div>

                <div className="flex items-center gap-2 shrink-0">
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                      rule.action === "VPN"
                        ? "bg-blue-500/10 text-blue-500 border border-blue-500/20"
                        : "bg-slate-500/10 text-slate-500 border border-slate-500/20"
                    }`}
                  >
                    {rule.action === "VPN" ? "VPN 隧道" : "本地直连"}
                  </span>

                  <button
                    onClick={() => onToggleRule(rule)}
                    disabled={isRoutingRunning}
                    className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed ${
                      rule.isEnabled
                        ? "bg-emerald-500/10 text-emerald-500 hover:bg-emerald-500/20"
                        : "bg-amber-500/10 text-amber-600 hover:bg-amber-500/20"
                    }`}
                    title={isRoutingRunning ? "分流运行中不可切换状态" : "切换生效状态"}
                  >
                    {rule.isEnabled ? "已生效" : "已暂停"}
                  </button>

                  <button
                    onClick={() => onDeleteRule(rule)}
                    disabled={isRoutingRunning}
                    className="p-1 rounded hover:bg-rose-500/10 text-rose-500 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                    title={isRoutingRunning ? "分流运行中不可删除" : "删除规则"}
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
