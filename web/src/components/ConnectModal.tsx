import React, { useState } from "react";
import { ArrowRightLeft, Globe2, X } from "lucide-react";
interface ConnectModalProps { isOpen: boolean; nodeName: string; switching: boolean; onClose: () => void; onConfirm: (mode: "global" | "split") => void; }
export const ConnectModal: React.FC<ConnectModalProps> = ({ isOpen, nodeName, switching, onClose, onConfirm }) => {
  const [mode, setMode] = useState<"global" | "split">("global");
  if (!isOpen) return null;
  return <div className="fixed inset-0 z-50 bg-black/40 flex items-center justify-center p-5"><div className="w-full max-w-xl rounded-2xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] shadow-2xl p-6">
    <div className="flex items-start justify-between gap-4"><div><h3 className="text-lg font-semibold">{switching ? "切换到新节点" : "选择连接方式"}</h3><p className="text-sm text-[#656d76] dark:text-[#8b949e] mt-1">{switching ? `先安全断开当前连接，再连接“${nodeName}”。` : `准备连接“${nodeName}”，请选择网络范围。`}</p></div><button aria-label="关闭" onClick={onClose}><X className="w-5 h-5" /></button></div>
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-5">
      <button onClick={() => setMode("global")} className={`text-left p-4 rounded-xl border ${mode === "global" ? "border-blue-500 bg-blue-500/10" : "border-[#d0d7de] dark:border-[#30363d]"}`}><div className="flex items-center gap-2 font-semibold"><Globe2 className="w-5 h-5 text-blue-500" />全局模式</div><p className="text-sm leading-6 mt-2 text-[#656d76] dark:text-[#8b949e]">所有网络流量都走 VPN。</p></button>
      <button onClick={() => setMode("split")} className={`text-left p-4 rounded-xl border ${mode === "split" ? "border-blue-500 bg-blue-500/10" : "border-[#d0d7de] dark:border-[#30363d]"}`}><div className="flex items-center gap-2 font-semibold"><ArrowRightLeft className="w-5 h-5 text-blue-500" />应用分流</div><p className="text-sm leading-6 mt-2 text-[#656d76] dark:text-[#8b949e]">只有指定走 VPN 的应用使用 VPN，其它应用保持直连。</p></button>
    </div><div className="mt-5 flex justify-end gap-3"><button onClick={onClose} className="px-4 py-2 rounded-lg border text-sm">取消</button><button onClick={() => onConfirm(mode)} className="px-4 py-2 rounded-lg bg-blue-600 text-white text-sm font-semibold">{switching ? "安全切换并连接" : "开始连接"}</button></div>
  </div></div>;
};
