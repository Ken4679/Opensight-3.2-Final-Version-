import React, { useState } from "react";
import { KeyRound, Shield, X } from "lucide-react";

interface CredentialModalProps {
  isOpen: boolean;
  hasSavedCreds: boolean;
  defaultUsername?: string;
  onClose: () => void;
  onSave: (u: string, p: string) => void;
  onClear: () => void;
}

export const CredentialModal: React.FC<CredentialModalProps> = ({
  isOpen,
  hasSavedCreds,
  defaultUsername = "",
  onClose,
  onSave,
  onClear,
}) => {
  const [username, setUsername] = useState(defaultUsername);
  const [password, setPassword] = useState("");

  if (!isOpen) return null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password.trim()) return;
    onSave(username.trim(), password.trim());
  };

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="p-5 rounded-2xl max-w-md w-full shadow-2xl border border-[#d0d7de] dark:border-[#30363d] bg-white dark:bg-[#161b22] text-slate-800 dark:text-slate-100 animate-in fade-in zoom-in-95 duration-150">
        <div className="flex items-center justify-between mb-3">
          <h3 className="font-bold text-sm flex items-center gap-2">
            <KeyRound className="w-4 h-4 text-blue-500" />
            <span>VPN 凭据管理 (DPAPI 硬件级加密)</span>
          </h3>
          <button onClick={onClose} className="p-1 rounded hover:bg-black/5 dark:hover:bg-white/5">
            <X className="w-4 h-4" />
          </button>
        </div>

        <p className="text-[11px] text-[#656d76] dark:text-[#8b949e] mb-4 flex items-center gap-1">
          <Shield className="w-3.5 h-3.5 text-emerald-500 shrink-0" />
          <span>凭据将使用 Windows 原生 DPAPI 硬件加密存储于本机，杜绝泄漏。</span>
        </p>

        <form onSubmit={handleSubmit} className="space-y-3 text-xs">
          <div>
            <label className="font-medium mb-1 block">VPN 用户名 / Token</label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-[#d0d7de] dark:border-[#30363d] bg-transparent text-xs focus:ring-1 focus:ring-blue-500 outline-none"
              placeholder="请输入 OpenVPN 认证账号"
              autoFocus
            />
          </div>

          <div>
            <label className="font-medium mb-1 block">VPN 密码 / 密钥</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-[#d0d7de] dark:border-[#30363d] bg-transparent text-xs focus:ring-1 focus:ring-blue-500 outline-none"
              placeholder="请输入 OpenVPN 认证密码"
            />
          </div>

          <div className="mt-5 flex items-center justify-between pt-3 border-t border-[#d0d7de] dark:border-[#30363d]">
            {hasSavedCreds ? (
              <button
                type="button"
                onClick={onClear}
                className="text-[11px] text-rose-500 hover:underline"
              >
                清除保存的凭据
              </button>
            ) : (
              <div />
            )}

            <div className="flex gap-2">
              <button
                type="button"
                onClick={onClose}
                className="px-3 py-1.5 rounded-lg border border-[#d0d7de] dark:border-[#30363d] text-xs font-medium hover:bg-black/5 dark:hover:bg-white/5"
              >
                取消
              </button>
              <button
                type="submit"
                disabled={!username || !password}
                className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white text-xs font-semibold shadow"
              >
                安全保存
              </button>
            </div>
          </div>
        </form>
      </div>
    </div>
  );
};
