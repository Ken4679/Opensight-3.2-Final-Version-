import React, { useEffect, useRef, useState } from "react";
import { Trash2, ArrowDown } from "lucide-react";

interface LogViewerProps {
  logs: string[];
  onClearLogs: () => void;
}

export const LogViewer: React.FC<LogViewerProps> = ({ logs, onClearLogs }) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  // 监听用户手动滚动行为
  const handleScroll = () => {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    // 离底端 40px 以内认为吸底
    const isAtBottom = scrollHeight - scrollTop - clientHeight < 40;
    setAutoScroll(isAtBottom);
  };

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs, autoScroll]);

  const scrollToBottom = () => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
      setAutoScroll(true);
    }
  };

  return (
    <div className="h-full rounded-xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] flex flex-col overflow-hidden shadow-sm">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#d0d7de] dark:border-[#30363d]">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold">运行与安全审计日志</span>
          <span className="text-[11px] text-[#656d76] dark:text-[#8b949e]">({logs.length} 条)</span>
        </div>

        <div className="flex items-center gap-2">
          {!autoScroll && (
            <button
              onClick={scrollToBottom}
              className="px-2 py-1 rounded text-[11px] bg-blue-500/10 text-blue-500 hover:bg-blue-500/20 flex items-center gap-1 transition-colors"
            >
              <ArrowDown className="w-3 h-3" />
              <span>滚动到底部</span>
            </button>
          )}

          <button
            onClick={onClearLogs}
            className="px-2.5 py-1 rounded text-xs text-rose-500 hover:bg-rose-500/10 flex items-center gap-1 transition-colors"
          >
            <Trash2 className="w-3 h-3" />
            <span>清空日志</span>
          </button>
        </div>
      </div>

      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 p-3 font-mono text-[11px] leading-relaxed overflow-y-auto bg-[#0d1117] text-[#8b949e] select-text"
      >
        {logs.length > 0 ? (
          logs.map((line, idx) => (
            <div key={idx} className="py-0.5 hover:bg-white/5 px-1 rounded transition-colors whitespace-pre-wrap break-all">
              {line}
            </div>
          ))
        ) : (
          <div className="text-center py-10 text-[#656d76]">暂无日志记录</div>
        )}
      </div>
    </div>
  );
};
