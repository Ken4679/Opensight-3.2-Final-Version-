import React, { useEffect, useState } from "react";
import { toast } from "../utils/toast";
import { ToastMessage } from "../types";
import { CheckCircle2, AlertCircle, Info, AlertTriangle, X } from "lucide-react";

export const ToastContainer: React.FC = () => {
  const [toasts, setToasts] = useState<ToastMessage[]>([]);

  useEffect(() => {
    return toast.subscribe(setToasts);
  }, []);

  if (toasts.length === 0) return null;

  return (
    <div className="fixed top-4 right-4 z-[9999] flex flex-col gap-2.5 max-w-sm w-full pointer-events-none">
      {toasts.map((t) => {
        let Icon = Info;
        let borderClass = "border-blue-500/30 bg-blue-950/80 text-blue-200";
        let iconClass = "text-blue-400";

        if (t.type === "success") {
          Icon = CheckCircle2;
          borderClass = "border-emerald-500/30 bg-emerald-950/80 text-emerald-200";
          iconClass = "text-emerald-400";
        } else if (t.type === "error") {
          Icon = AlertCircle;
          borderClass = "border-rose-500/30 bg-rose-950/80 text-rose-200";
          iconClass = "text-rose-400";
        } else if (t.type === "warning") {
          Icon = AlertTriangle;
          borderClass = "border-amber-500/30 bg-amber-950/80 text-amber-200";
          iconClass = "text-amber-400";
        }

        return (
          <div
            key={t.id}
            className={`pointer-events-auto flex items-start justify-between gap-3 p-3.5 rounded-xl border backdrop-blur-md shadow-2xl transition-all animate-in fade-in slide-in-from-top-2 duration-200 ${borderClass}`}
          >
            <div className="flex items-start gap-2.5 min-w-0">
              <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${iconClass}`} />
              <div className="min-w-0">
                <div className="text-xs font-semibold leading-snug">{t.title}</div>
                {t.description && (
                  <div className="text-[11px] opacity-80 mt-0.5 leading-relaxed break-words">
                    {t.description}
                  </div>
                )}
              </div>
            </div>
            <button
              onClick={() => toast.dismiss(t.id)}
              className="p-1 rounded hover:bg-white/10 opacity-70 hover:opacity-100 transition-opacity"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        );
      })}
    </div>
  );
};
