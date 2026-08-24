import React from "react";

import { ArrowDown, ArrowUp, Globe, KeyRound, FolderOpen, RefreshCw, Play, Square } from "lucide-react";

import { TrafficData, VPNStatus } from "../types";

import { formatSpeed } from "../utils/format";



interface TopBarProps {

  activeTab: string;

  vpnStatus: VPNStatus;

  traffic: TrafficData;

  isProbing: boolean;

  probePercentage: number;

  hasSavedCreds: boolean;

  onOpenNetModal: () => void;

  onOpenCredModal: () => void;

  onOpenFolder: () => void;

  onImportProfiles: () => void;

  onStartProbing: () => void;

  onStopProbing: () => void;

}



export const TopBar: React.FC<TopBarProps> = ({

  activeTab,

  vpnStatus,

  traffic,

  isProbing,

  probePercentage,

  hasSavedCreds,

  onOpenNetModal,

  onOpenCredModal,

  onOpenFolder,

  onImportProfiles,

  onStartProbing,

  onStopProbing,

}) => {

  const getTitle = () => {

    switch (activeTab) {

      case "nodes":

        return "节点质量评估与智能调度";

      case "routing":

        return "应用级分流与规则隔离";

      case "logs":

        return "本地安全与运行日志";

      case "settings":

        return "组件维护与环境设置";

      default:

        return "OpenSight";

    }

  };



  return (

    <header className="h-16 border-b px-6 flex items-center justify-between shrink-0 border-[#d0d7de] dark:border-[#30363d] bg-[#f6f8fa] dark:bg-[#0d1117] transition-colors">

      <div>

        <h1 className="text-base font-bold tracking-tight text-slate-800 dark:text-slate-100">{getTitle()}</h1>

        <p className="text-xs text-[#656d76] dark:text-[#8b949e]">安全测速：只测网络质量，不建立 VPN 隧道</p>

      </div>



      <div className="flex items-center space-x-2">

        {/* 实时流量监控徽标 */}

        {vpnStatus.isConnected && (

          <div className="flex items-center space-x-2.5 px-2.5 py-1 rounded-lg bg-black/5 dark:bg-white/5 border border-[#d0d7de] dark:border-[#30363d] text-xs font-mono">

            <div className="flex items-center space-x-1 text-emerald-500 font-medium" title="下行 / 下载速度">

              <ArrowDown className="w-3 h-3 animate-pulse" />

              <span>{formatSpeed(traffic.downloadSpeedBps)}</span>

            </div>

            <div className="flex items-center space-x-1 text-blue-500 font-medium" title="上行 / 上传速度">

              <ArrowUp className="w-3 h-3" />

              <span>{formatSpeed(traffic.uploadSpeedBps)}</span>

            </div>

          </div>

        )}



        <button

          onClick={onOpenNetModal}

          className="px-3 py-2 text-sm font-medium rounded-lg border border-[#d0d7de] dark:border-[#30363d] hover:bg-black/5 dark:hover:bg-white/5 flex items-center space-x-1 text-[#656d76] dark:text-[#8b949e] hover:text-slate-900 dark:hover:text-white transition-colors"

          title="查看出口公网 IP 与生效 DNS"

        >

          <Globe className="w-3.5 h-3.5 text-blue-500" />

          <span>网络状态</span>

        </button>



        <button

          onClick={onOpenCredModal}

          className="px-3 py-2 text-sm font-medium rounded-lg border border-[#d0d7de] dark:border-[#30363d] hover:bg-black/5 dark:hover:bg-white/5 flex items-center space-x-1 text-[#656d76] dark:text-[#8b949e] hover:text-slate-900 dark:hover:text-white transition-colors"

        >

          <KeyRound className="w-3.5 h-3.5 text-amber-500" />

          <span>{hasSavedCreds ? "已存凭据" : "配置凭据"}</span>

        </button>



        {activeTab === "nodes" && (

          <>

            <button

              onClick={onOpenFolder}

              className="px-3 py-2 text-sm font-medium rounded-lg border border-[#d0d7de] dark:border-[#30363d] hover:bg-black/5 dark:hover:bg-white/5 flex items-center space-x-1 text-[#656d76] dark:text-[#8b949e] hover:text-slate-900 dark:hover:text-white transition-colors"

              title="打开存放 .ovpn 配置的目录"

            >

              <FolderOpen className="w-3.5 h-3.5" />

              <span>配置目录</span>

            </button>



            <button

              onClick={onImportProfiles}

              className="px-3 py-2 text-sm font-medium rounded-lg border border-[#d0d7de] dark:border-[#30363d] hover:bg-black/5 dark:hover:bg-white/5 flex items-center space-x-1 text-[#656d76] dark:text-[#8b949e] hover:text-slate-900 dark:hover:text-white transition-colors"

            >

              <RefreshCw className="w-3.5 h-3.5" />

              <span>重新导入</span>

            </button>



            {!isProbing ? (

              <button

                onClick={onStartProbing}

                className="bg-blue-600 hover:bg-blue-700 text-white px-3 py-1 rounded-lg text-xs font-semibold shadow flex items-center space-x-1.5 transition-all"

              >

                <Play className="w-3 h-3 fill-current" />

                <span>批量测速</span>

              </button>

            ) : (

              <button

                onClick={onStopProbing}

                className="bg-rose-600 hover:bg-rose-700 text-white px-3 py-1 rounded-lg text-xs font-semibold shadow flex items-center space-x-1.5 transition-all"

              >

                <Square className="w-3 h-3 fill-current" />

                <span>停止 ({probePercentage.toFixed(0)}%)</span>

              </button>

            )}

          </>

        )}

      </div>

    </header>

  );

};
