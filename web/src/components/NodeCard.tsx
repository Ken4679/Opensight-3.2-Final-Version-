import React from "react";

import { NodeItem } from "../types";

import { formatLatency, getLatencyColor } from "../utils/format";

import { Power, Zap, ShieldCheck } from "lucide-react";



interface NodeCardProps {

  node: NodeItem;

  isConnected: boolean;

  onConnect: (nodeId: string) => void;

  onDisconnect: () => void;

}



export const NodeCard: React.FC<NodeCardProps> = React.memo(

  ({ node, isConnected, onConnect, onDisconnect }) => {

    return (

      <div

        className={`p-4 rounded-2xl border transition-all duration-200 bg-white dark:bg-[#161b22] ${

          isConnected

            ? "border-emerald-500/50 ring-1 ring-emerald-500/20 shadow-md"

            : "border-[#d0d7de] dark:border-[#30363d] hover:border-blue-500/40 hover:shadow-sm"

        }`}

      >

        <div className="flex justify-between items-start gap-2">

          <div className="min-w-0">

            <div className="font-semibold text-sm text-slate-800 dark:text-slate-100 truncate flex items-center gap-1.5">

              <span>{node.serverName}</span>

              {isConnected && (

                <span className="flex items-center gap-0.5 px-1.5 py-0.2 rounded bg-emerald-500/10 text-emerald-500 text-[10px] font-bold">

                  <ShieldCheck className="w-3 h-3" />

                  已连接

                </span>

              )}

            </div>

            <div className="text-xs text-[#656d76] dark:text-[#8b949e] mt-0.5 flex items-center gap-1">

              <span>{node.country}</span>

              <span>•</span>

              <span className="uppercase text-[10px] opacity-75">{node.protocol}/{node.port}</span>

            </div>

          </div>



          <div

            className={`px-2 py-0.5 rounded text-xs font-bold border shrink-0 ${getLatencyColor(

              node.bestTcpLatency,

              node.isReachable

            )}`}

          >

            {formatLatency(node.bestTcpLatency, node.isReachable)}

          </div>

        </div>



        {/* 场景推荐标签 */}

        <div className="mt-2.5 py-1 px-2 rounded-md bg-black/5 dark:bg-white/5 border border-black/5 dark:border-white/5">

          <p className="text-xs text-blue-600 dark:text-blue-400 font-medium truncate" title={node.explanation}>

            {node.explanation || "等待测速评分"}

          </p>

        </div>



        {/* 底部评分与连接操作 */}

        <div className="mt-3 flex items-center justify-between text-xs pt-2 border-t border-[#d0d7de] dark:border-[#30363d]">

          <div className="flex items-center gap-1 text-xs text-[#656d76] dark:text-[#8b949e]">

            <Zap className="w-3 h-3 text-amber-500" />

            <span>评分:</span>

            <b className="text-blue-600 dark:text-blue-400 font-semibold">{node.overallScore}</b>

          </div>



          {isConnected ? (

            <button

              onClick={onDisconnect}

              className="px-3.5 py-1 rounded-md bg-rose-600 hover:bg-rose-700 text-white font-medium text-xs transition-all shadow-sm flex items-center gap-1"

            >

              <Power className="w-3 h-3" />

              <span>断开</span>

            </button>

          ) : (

            <button

              onClick={() => onConnect(node.nodeId)}

              className="px-3.5 py-1 rounded-md bg-blue-600/10 text-blue-600 dark:text-blue-400 hover:bg-blue-600 hover:text-white font-medium text-xs transition-all"

            >

              连接

            </button>

          )}

        </div>

      </div>

    );

  },

  (prev, next) => {

    return (

      prev.isConnected === next.isConnected &&

      prev.node.nodeId === next.node.nodeId &&

      prev.node.overallScore === next.node.overallScore &&

      prev.node.bestTcpLatency === next.node.bestTcpLatency &&

      prev.node.isReachable === next.node.isReachable &&

      prev.node.explanation === next.node.explanation &&

      prev.node.protocol === next.node.protocol &&

      prev.node.port === next.node.port &&

      prev.node.lastMeasuredAt === next.node.lastMeasuredAt &&

      prev.onConnect === next.onConnect &&

      prev.onDisconnect === next.onDisconnect

    );

  }

);



NodeCard.displayName = "NodeCard";
