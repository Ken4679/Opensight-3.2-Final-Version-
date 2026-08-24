export function formatSpeed(bytesPerSec: number): string {
  if (!bytesPerSec || bytesPerSec <= 0) return "0.0 KB/s";
  if (bytesPerSec < 1024 * 1024) {
    return `${(bytesPerSec / 1024).toFixed(1)} KB/s`;
  }
  return `${(bytesPerSec / (1024 * 1024)).toFixed(2)} MB/s`;
}

export function formatLatency(latency: number | null, isReachable: boolean): string {
  if (!isReachable || latency === null) return "不可达";
  return `${Math.round(latency)} ms`;
}

export function getLatencyColor(latency: number | null, isReachable: boolean): string {
  if (!isReachable || latency === null) return "text-rose-500 bg-rose-500/10 border-rose-500/20";
  if (latency <= 50) return "text-emerald-500 bg-emerald-500/10 border-emerald-500/20";
  if (latency <= 100) return "text-blue-500 bg-blue-500/10 border-blue-500/20";
  if (latency <= 180) return "text-amber-500 bg-amber-500/10 border-amber-500/20";
  return "text-orange-500 bg-orange-500/10 border-orange-500/20";
}
