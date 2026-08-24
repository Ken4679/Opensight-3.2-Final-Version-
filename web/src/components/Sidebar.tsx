import React from "react";

import { Activity, Shuffle, FileText, Settings, Shield, Moon, Sun, Power, ShieldCheck, ShieldX, LoaderCircle, CircleOff } from "lucide-react";

import { VPNStatus } from "../types";



interface SidebarProps {

  activeTab: string;

  setActiveTab: (tab: string) => void;

  isDark: boolean;

  setIsDark: (dark: boolean) => void;

  vpnStatus: VPNStatus;

  onDisconnect: () => void;

}



export const Sidebar: React.FC<SidebarProps> = ({

  activeTab,

  setActiveTab,

  isDark,

  setIsDark,

  vpnStatus,

  onDisconnect,

}) => {

  const navItems = [

    { id: "nodes", label: "节点测速", icon: Activity },

    { id: "routing", label: "应用分流", icon: Shuffle },

    { id: "logs", label: "运行日志", icon: FileText },

    { id: "settings", label: "系统设置", icon: Settings },

  ];



  const getVisual = () => {

    const code = vpnStatus.code || (vpnStatus.isConnected ? "CONNECTED" : "DISCONNECTED");

    if (code === "CONNECTED") return { icon: ShieldCheck, label: vpnStatus.state || "VPN 已连接", cls: "text-emerald-500" };

    if (code === "FAILED") return { icon: ShieldX, label: vpnStatus.state || "连接失败", cls: "text-rose-500" };

    if (code === "CONNECTING" || code === "STARTING" || code === "VALIDATING") return { icon: LoaderCircle, label: vpnStatus.state || "正在连接", cls: "text-amber-500 animate-spin" };

    if (code === "AUTHENTICATING") return { icon: Shield, label: vpnStatus.state || "正在验证凭据", cls: "text-amber-500" };

    if (code === "DISCONNECTING") return { icon: CircleOff, label: vpnStatus.state || "正在断开", cls: "text-amber-500" };

    if (vpnStatus.runtimeReady === false) return { icon: ShieldX, label: "核心未安装", cls: "text-rose-500" };
    if (vpnStatus.driverReady === false) return { icon: ShieldX, label: "驱动未安装", cls: "text-amber-500" };
    return { icon: ShieldX, label: "未连接", cls: "text-[#656d76] dark:text-[#8b949e]" };

  };



  const visual = getVisual();

  const VpnIcon = visual.icon;



  return (

    <aside className="w-56 border-r flex flex-col justify-between p-3.5 shrink-0 select-none border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] transition-colors duration-200">

      <div className="space-y-5">

        <div className="flex items-center space-x-2.5 px-2 pt-1">

          <div className="p-1.5 rounded-lg bg-blue-500/10 text-blue-500">

            <Shield className="w-5 h-5" />

          </div>

          <div>

            <div className="font-bold text-sm tracking-wide leading-tight">OpenSight</div>

            <div className="text-[10px] text-blue-500 font-semibold tracking-wider uppercase">便携版</div>

          </div>

        </div>



        <nav className="space-y-1">

          {navItems.map((item) => {

            const Icon = item.icon;

            const isActive = activeTab === item.id;

            return (

              <button

                key={item.id}

                onClick={() => setActiveTab(item.id)}

                className={`w-full flex items-center space-x-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-all ${

                  isActive

                    ? "bg-blue-600/15 text-blue-600 dark:text-blue-400 font-semibold shadow-sm"

                    : "text-[#656d76] dark:text-[#8b949e] hover:bg-black/5 dark:hover:bg-[#21262d]"

                }`}

              >

                <Icon className={`w-4 h-4 ${isActive ? "text-blue-600 dark:text-blue-400" : ""}`} />

                <span>{item.label}</span>

              </button>

            );

          })}

        </nav>

      </div>



      <div className="border-t pt-3 border-[#d0d7de] dark:border-[#30363d] space-y-2">

        <div className="flex items-center justify-between px-1">

          <button

            onClick={() => setIsDark(!isDark)}

            className="p-1.5 rounded-lg text-[#656d76] dark:text-[#8b949e] hover:bg-black/5 dark:hover:bg-[#21262d] transition-colors"

            title={isDark ? "切换为浅色模式" : "切换为深色模式"}

          >

            {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4 text-slate-700" />}

          </button>



          <div className="flex items-center gap-1.5 min-w-0">

            <span className="truncate max-w-[110px] flex items-center gap-1.5 text-xs">

              <VpnIcon className={`w-3.5 h-3.5 shrink-0 ${visual.cls}`} />

              <span className="truncate text-[#656d76] dark:text-[#8b949e]">{visual.label}</span>

            </span>

            {vpnStatus.isConnected && (

              <button

                onClick={onDisconnect}

                className="p-1 rounded hover:bg-rose-500/15 text-rose-500 transition-colors shrink-0"

                title="断开当前 VPN 连接"

              >

                <Power className="w-3.5 h-3.5" />

              </button>

            )}

          </div>

        </div>

      </div>

    </aside>

  );

};
