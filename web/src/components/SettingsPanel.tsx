import React, { useState } from "react";
import { Wrench, Trash2, ShieldAlert, AlertTriangle, X, CheckCircle2, ShieldCheck } from "lucide-react";

interface SettingsPanelProps {
  isVpnConnected: boolean;
  onRepairOpenVPN: () => void;
  onUninstallAll: (purgeData: boolean) => void;
}

export const SettingsPanel: React.FC<SettingsPanelProps> = ({
  isVpnConnected,
  onRepairOpenVPN,
  onUninstallAll,
}) => {
  const [confirmRepair, setConfirmRepair] = useState(false);
  const [confirmUninstall, setConfirmUninstall] = useState(false);
  const [purgeData, setPurgeData] = useState(true);

  return (
    <div className="max-w-3xl space-y-6">
      {/* 驱动维护卡片 */}
      <div className="p-6 rounded-2xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] space-y-4 shadow-sm">
        <h3 className="font-semibold text-base flex items-center gap-2 text-slate-800 dark:text-slate-200">
          <Wrench className="w-5 h-5 text-blue-500" />
          OpenVPN 驱动维护与状态修复
        </h3>
        <p className="text-sm leading-6 text-[#656d76] dark:text-[#8b949e]">
          遇到虚拟网卡驱动丢失、异常或无法连接时，可以基于本地已验证的官方安装包快速修复驱动。修复过程中网络可能会短暂中断。
        </p>
        {isVpnConnected && (
          <div className="rounded-xl bg-amber-500/10 border border-amber-500/20 p-3 text-sm leading-6 text-amber-700 dark:text-amber-300">
            当前 VPN 正在连接。请先在首页断开 VPN 连接，再执行驱动修复。
          </div>
        )}
        <button
          disabled={isVpnConnected}
          onClick={() => setConfirmRepair(true)}
          className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-semibold transition-colors"
        >
          一键修复驱动
        </button>
      </div>

      {/* 卸载清理卡片 */}
      <div className="p-6 rounded-2xl border border-rose-500/30 bg-rose-950/10 dark:bg-rose-950/20 space-y-4 shadow-sm">
        <div className="flex items-center justify-between">
          <h3 className="font-semibold text-base flex items-center gap-2 text-rose-500">
            <ShieldAlert className="w-5 h-5" />
            一键彻底卸载与安全清理
          </h3>
          <span className="text-xs px-2.5 py-1 rounded-full font-medium bg-rose-500/15 text-rose-500 border border-rose-500/20">
            零残留闭环
          </span>
        </div>
        <p className="text-sm leading-6 text-[#656d76] dark:text-[#8b949e]">
          安全终止 OpenSight 进程，清理 TUN 虚拟网卡、专用防火墙规则、分流路由，并根据安装归属权清理 OpenVPN 驱动组件。支持正常卸载与彻底抹除（Purge）两种模式。
        </p>
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <button
            onClick={() => {
              setPurgeData(false);
              setConfirmUninstall(true);
            }}
            className="px-4 py-2.5 bg-slate-200 hover:bg-slate-300 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-800 dark:text-slate-200 rounded-lg text-sm font-semibold transition-colors"
          >
            正常卸载 (保留配置)
          </button>
          <button
            onClick={() => {
              setPurgeData(true);
              setConfirmUninstall(true);
            }}
            className="px-4 py-2.5 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-sm font-semibold flex items-center gap-2 transition-colors"
          >
            <Trash2 className="w-4 h-4" />
            彻底抹除并卸载 (推荐)
          </button>
        </div>
      </div>

      {/* 修复驱动确认弹窗 */}
      {confirmRepair && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm flex items-center justify-center p-5">
          <div className="w-full max-w-lg rounded-2xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] shadow-2xl p-6">
            <div className="flex items-start justify-between gap-4">
              <div className="flex gap-3">
                <AlertTriangle className="w-6 h-6 mt-0.5 text-amber-500 shrink-0" />
                <div>
                  <h4 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                    确认开始修复 OpenVPN 驱动？
                  </h4>
                  <p className="text-sm leading-6 text-[#656d76] dark:text-[#8b949e] mt-2">
                    该操作将重置虚拟网卡驱动，仅使用便携包内置已严格验证的官方安装包，绝不会向外网下载未知二进制。
                  </p>
                </div>
              </div>
              <button aria-label="关闭" onClick={() => setConfirmRepair(false)} className="text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>
            <div className="mt-6 flex justify-end gap-3">
              <button
                onClick={() => setConfirmRepair(false)}
                className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 text-sm font-medium hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                取消
              </button>
              <button
                onClick={() => {
                  setConfirmRepair(false);
                  onRepairOpenVPN();
                }}
                className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold transition-colors"
              >
                开始修复
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 卸载确认弹窗 */}
      {confirmUninstall && (
        <div className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm flex items-center justify-center p-5">
          <div className="w-full max-w-lg rounded-2xl border border-rose-500/30 bg-white dark:bg-[#161b22] shadow-2xl p-6 space-y-4">
            <div className="flex items-start justify-between gap-4">
              <div className="flex gap-3">
                <ShieldAlert className="w-6 h-6 mt-0.5 text-rose-500 shrink-0" />
                <div>
                  <h4 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
                    {purgeData ? "确认彻底抹除并卸载 OpenSight？" : "确认正常卸载 OpenSight？"}
                  </h4>
                  <p className="text-sm leading-6 text-[#656d76] dark:text-[#8b949e] mt-1">
                    系统将自动停止所有 VPN/分流服务、清理虚拟网卡、安全移除防火墙规则并验证零残留。
                  </p>
                </div>
              </div>
              <button aria-label="关闭" onClick={() => setConfirmUninstall(false)} className="text-slate-400 hover:text-slate-600">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="p-3.5 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/50 space-y-2">
              <label className="flex items-center gap-3 cursor-pointer text-sm font-medium text-slate-800 dark:text-slate-200">
                <input
                  type="checkbox"
                  checked={purgeData}
                  onChange={(e) => setPurgeData(e.target.checked)}
                  className="w-4 h-4 rounded text-rose-600 focus:ring-rose-500 border-slate-300"
                />
                彻底抹除数据 (抹除配置文件、节点数据与凭据)
              </label>
              <p className="text-xs text-[#656d76] dark:text-[#8b949e] pl-7">
                {purgeData
                  ? "将删除所有节点配置、DPAPI 加密凭据与运行日志，达到接近从未安装过的状态。"
                  : "将保留 data/ 目录中的节点配置文件，以便后续重新使用。"}
              </p>
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setConfirmUninstall(false)}
                className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-700 text-sm font-medium hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                取消
              </button>
              <button
                onClick={() => {
                  setConfirmUninstall(false);
                  onUninstallAll(purgeData);
                }}
                className={`px-4 py-2 rounded-lg text-white text-sm font-semibold transition-colors ${
                  purgeData ? "bg-rose-600 hover:bg-rose-700" : "bg-blue-600 hover:bg-blue-700"
                }`}
              >
                开始卸载
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
