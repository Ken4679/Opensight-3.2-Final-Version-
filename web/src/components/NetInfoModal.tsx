import React from "react";

import { NetworkSnapshot } from "../types";

import { Globe, ShieldCheck, Shield, Network, X } from "lucide-react";



interface NetInfoModalProps {

  isOpen: boolean;

  isConnected: boolean;

  snapshot?: NetworkSnapshot;

  onClose: () => void;

}



export const NetInfoModal: React.FC<NetInfoModalProps> = ({

  isOpen,

  isConnected,

  snapshot,

  onClose,

}) => {

  if (!isOpen) return null;



  return (

    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-6">

      <div className="p-5 rounded-2xl max-w-lg w-full shadow-2xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] text-slate-800 dark:text-slate-100 animate-in fade-in zoom-in-95 duration-150">

        <div className="flex items-center justify-between mb-2">

          <h3 className="font-bold text-sm flex items-center gap-2">

            <Network className="w-4 h-4 text-blue-500" />

            <span>网络出口与 DNS 诊断快照</span>

          </h3>

          <button onClick={onClose} className="p-1 rounded hover:bg-black/5 dark:hover:bg-white/5">

            <X className="w-4 h-4" />

          </button>

        </div>



        <p className="text-[11px] text-[#656d76] dark:text-[#8b949e] mb-4">

          实时监测物理网卡与 VPN 虚拟网卡环境，确保无 DNS/IPv6 泄漏。

        </p>



        <div className="space-y-3 text-sm">

          {/* IP 出口 */}

          <div className="p-3 rounded-xl bg-black/5 dark:bg-white/5 border border-black/5 dark:border-white/5 space-y-1.5">

            <div className="font-semibold text-blue-600 dark:text-blue-400 flex items-center gap-1.5">

              <Globe className="w-3.5 h-3.5" />

              <span>公网出口 IP 状态</span>

            </div>

            <div className="grid grid-cols-2 gap-2 pt-1 border-t border-black/5 dark:border-white/5">

              <div>

                <span className="text-[11px] text-[#656d76] dark:text-[#8b949e]">物理宽带原始 IP:</span>

                <div className="font-mono mt-0.5">{snapshot?.direct_ip || "未抓取"}</div>

              </div>

              <div>

                <span className="text-[11px] text-[#656d76] dark:text-[#8b949e]">当前实际出口 IP:</span>

                <div className={`font-mono font-bold mt-0.5 ${isConnected ? "text-emerald-500" : ""}`}>

                  {isConnected ? snapshot?.vpn_ip || "已加密防护" : snapshot?.direct_ip || "本地直连"}

                </div>

              </div>

            </div>

          </div>



          {/* DNS 配置 */}

          <div className="p-3 rounded-xl bg-black/5 dark:bg-white/5 border border-black/5 dark:border-white/5 space-y-1.5">

            <div className="font-semibold text-blue-600 dark:text-blue-400 flex items-center gap-1.5">

              <ShieldCheck className="w-3.5 h-3.5" />

              <span>DNS 服务器配置</span>

            </div>

            <div className="grid grid-cols-2 gap-2 pt-1 border-t border-black/5 dark:border-white/5">

              <div>

                <span className="text-[11px] text-[#656d76] dark:text-[#8b949e]">本地 ISP DNS:</span>

                <div className="font-mono mt-0.5 truncate" title={snapshot?.direct_dns?.join(", ")}>

                  {snapshot?.direct_dns?.join(", ") || "系统默认"}

                </div>

              </div>

              <div>

                <span className="text-[11px] text-[#656d76] dark:text-[#8b949e]">生效 DNS:</span>

                <div className={`font-mono font-bold mt-0.5 truncate ${isConnected ? "text-emerald-500" : ""}`}>

                  {isConnected ? snapshot?.vpn_dns?.join(", ") || "安全隧道 DNS" : "本地系统 DNS"}

                </div>

              </div>

            </div>

          </div>



          {/* 防泄漏状态 */}

          <div className="p-3 rounded-xl bg-black/5 dark:bg-white/5 border border-black/5 dark:border-white/5 space-y-1.5">

            <div className="font-semibold text-blue-600 dark:text-blue-400 flex items-center gap-1.5">

              <Shield className="w-3.5 h-3.5" />

              <span>网卡与防泄漏机制</span>

            </div>

            <div className="grid grid-cols-3 gap-2 pt-1 border-t border-black/5 dark:border-white/5">

              <div>

                <span className="text-[11px] text-[#656d76] dark:text-[#8b949e]">物理网卡:</span>

                <div className="font-mono mt-0.5 truncate">{snapshot?.direct_interface || "检测中"}</div>

              </div>

              <div>

                <span className="text-[11px] text-[#656d76] dark:text-[#8b949e]">VPN 虚拟网卡:</span>

                <div className="font-mono mt-0.5 truncate">{snapshot?.vpn_interface || "未激活"}</div>

              </div>

              <div>

                <span className="text-[11px] text-[#656d76] dark:text-[#8b949e]">KillSwitch:</span>

                <div className="font-mono text-emerald-500 font-bold mt-0.5">

                  {isConnected ? "已激活" : "待命"}

                </div>

              </div>

            </div>

          </div>

        </div>



        <div className="mt-5 flex justify-end">

          <button

            onClick={onClose}

            className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold shadow"

          >

            完成

          </button>

        </div>

      </div>

    </div>

  );

};
