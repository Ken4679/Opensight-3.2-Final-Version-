import React, { useState } from "react";
import { Wrench, Trash2, ShieldAlert, AlertTriangle, X } from "lucide-react";
interface SettingsPanelProps { isVpnConnected: boolean; onRepairOpenVPN: () => void; onUninstallAll: () => void; }
export const SettingsPanel: React.FC<SettingsPanelProps> = ({ isVpnConnected, onRepairOpenVPN, onUninstallAll }) => {
  const [confirmRepair, setConfirmRepair] = useState(false);
  return <div className="max-w-3xl space-y-5">
    <div className="p-5 rounded-2xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] space-y-3 shadow-sm">
      <h3 className="font-semibold text-base flex items-center gap-2 text-slate-800 dark:text-slate-200"><Wrench className="w-5 h-5 text-blue-500" />OpenVPN 驱动维护</h3>
      <p className="text-sm leading-6 text-[#656d76] dark:text-[#8b949e]">遇到虚拟网卡异常或无法连接时，可以校验并重新安装内置的官方驱动。修复过程中网络可能短暂中断。</p>
      {isVpnConnected && <div className="rounded-xl bg-amber-500/10 border border-amber-500/20 p-3 text-sm leading-6 text-amber-700 dark:text-amber-300">当前 VPN 正在连接。请先断开 VPN，再开始修复，避免网络被意外中断。</div>}
      <button disabled={isVpnConnected} onClick={() => setConfirmRepair(true)} className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed text-white rounded-lg text-sm font-semibold">一键修复驱动</button>
    </div>
    <div className="p-5 rounded-2xl border border-rose-500/30 bg-rose-950/10 dark:bg-rose-950/20 space-y-3">
      <h3 className="font-semibold text-base flex items-center gap-2 text-rose-500"><ShieldAlert className="w-5 h-5" />危险操作</h3>
      <p className="text-sm leading-6 text-[#656d76] dark:text-[#8b949e]">彻底清理 OpenSight-TUN 虚拟网卡、防火墙规则和便携数据。执行后应用会关闭，相关配置不会保留。</p>
      <button onClick={onUninstallAll} className="px-4 py-2.5 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-sm font-semibold flex items-center gap-2"><Trash2 className="w-4 h-4" />彻底清理并卸载</button>
    </div>
    {confirmRepair && <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-5"><div className="w-full max-w-lg rounded-2xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] shadow-2xl p-6">
      <div className="flex items-start justify-between gap-4"><div className="flex gap-3"><AlertTriangle className="w-6 h-6 mt-0.5 text-amber-500 shrink-0" /><div><h4 className="text-lg font-semibold">开始修复驱动？</h4><p className="text-sm leading-6 text-[#656d76] dark:text-[#8b949e] mt-1">这一步会修改 Windows 虚拟网卡，网络可能短暂中断。修复只使用本机已有的 OpenVPN 安装包，不会为了修复去外网下载。</p></div></div><button aria-label="关闭" onClick={() => setConfirmRepair(false)}><X className="w-5 h-5" /></button></div>
      <div className="mt-5 flex justify-end gap-3"><button onClick={() => setConfirmRepair(false)} className="px-4 py-2 rounded-lg border text-sm">取消</button><button onClick={() => { setConfirmRepair(false); onRepairOpenVPN(); }} className="px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-semibold">继续修复</button></div>
    </div></div>}
  </div>;
};
