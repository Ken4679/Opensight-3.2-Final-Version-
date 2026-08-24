import React from "react";
import { ProbeProgressData } from "../types";
import { Activity } from "lucide-react";

interface ProbeProgressProps {
  isProbing: boolean;
  progress: ProbeProgressData;
}

export const ProbeProgress: React.FC<ProbeProgressProps> = ({ isProbing, progress }) => {
  if (!isProbing) return null;

  return (
    <div className="relative border-b border-blue-500/20 bg-blue-500/5 px-6 py-2 flex items-center justify-between text-xs overflow-hidden">
      <div
        className="absolute top-0 bottom-0 left-0 bg-blue-500/15 transition-all duration-300 pointer-events-none"
        style={{ width: `${progress.percentage}%` }}
      />
      <div className="relative z-10 flex items-center gap-2 text-blue-600 dark:text-blue-400 font-medium">
        <Activity className="w-3.5 h-3.5 animate-pulse" />
        <span>
          正在安全测速: <b className="font-semibold">{progress.currentNode || "初始化"}</b> ({progress.stage || "探测中"})
        </span>
      </div>
      <div className="relative z-10 font-mono text-xs text-blue-600 dark:text-blue-400 font-bold">
        {progress.percentage.toFixed(1)}%
      </div>
    </div>
  );
};
