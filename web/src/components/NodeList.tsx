import React from "react";

import { NodeItem } from "../types";

import { NodeCard } from "./NodeCard";

import { Inbox } from "lucide-react";



interface NodeListProps {
  nodes: NodeItem[];
  loading: boolean;
  connectedNodeId: string | null;
  isConnected: boolean;
  onConnect: (nodeId: string) => void;
  onDisconnect: () => void;
  recentNodeIds?: string[];
}

export const NodeList: React.FC<NodeListProps> = ({
  nodes,
  loading,
  connectedNodeId,
  isConnected,
  onConnect,
  onDisconnect,
  recentNodeIds = [],
}) => {

  if (loading && nodes.length === 0) {

    return (

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">

        {[...Array(6)].map((_, i) => (

          <div

            key={i}

            className="p-4 rounded-xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] animate-pulse space-y-3"

          >

            <div className="flex justify-between">

              <div className="h-4 bg-slate-200 dark:bg-slate-800 rounded w-1/3" />

              <div className="h-4 bg-slate-200 dark:bg-slate-800 rounded w-12" />

            </div>

            <div className="h-3 bg-slate-100 dark:bg-slate-800/60 rounded w-1/2" />

            <div className="h-6 bg-slate-100 dark:bg-slate-800/60 rounded w-full" />

          </div>

        ))}

      </div>

    );

  }



  if (nodes.length === 0) {

    return (

      <div className="h-64 flex flex-col items-center justify-center text-center p-6 rounded-2xl border border-dashed border-[#d0d7de] dark:border-[#30363d]">

        <Inbox className="w-10 h-10 text-[#8b949e] mb-2 opacity-60" />

        <div className="text-sm font-semibold text-slate-700 dark:text-slate-300">暂未发现 OpenVPN 节点</div>

        <p className="text-xs text-[#656d76] dark:text-[#8b949e] mt-1 max-w-sm">

          请点击右上角「配置目录」放入 .ovpn 文件，然后点击「重新导入」开始测速。

        </p>

      </div>

    );

  }



  const safeRecentIds = Array.isArray(recentNodeIds) ? recentNodeIds : [];
  const orderedNodes = [...nodes].sort((a, b) => {
    const rank = (n: NodeItem) => (n.nodeId === connectedNodeId && isConnected) ? 0 : (safeRecentIds.includes(n.nodeId) ? 1 : 2);
    const ar = rank(a); const br = rank(b);
    if (ar !== br) return ar - br;
    if (ar === 1) return safeRecentIds.indexOf(a.nodeId) - safeRecentIds.indexOf(b.nodeId);
    return a.serverName.localeCompare(b.serverName);
  });

  return (

    <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">

      {orderedNodes.map((node) => (

        <NodeCard

          key={node.nodeId}

          node={node}

          isConnected={isConnected && connectedNodeId === node.nodeId}

          onConnect={onConnect}

          onDisconnect={onDisconnect}

        />

      ))}

    </div>

  );

};
