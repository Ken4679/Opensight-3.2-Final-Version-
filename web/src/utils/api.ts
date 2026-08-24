import { InstalledApp, NodeItem, RoutingRule, VPNStatus, TrafficData } from "../types";



export class ApiClient {

  private port: number;

  private token: string;



  constructor(port: number, token: string = "") {

    this.port = port;

    this.token = token;

  }



  private get headers(): HeadersInit {

    return {

      "Content-Type": "application/json",

      ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),

    };

  }



  private url(path: string): string {
    if (typeof window !== "undefined") {
      const hostname = window.location.hostname;
      if (hostname !== "127.0.0.1" && hostname !== "localhost") {
        return path;
      }
      if (window.location.port && parseInt(window.location.port) === this.port) {
        return path;
      }
    }
    return `http://127.0.0.1:${this.port}${path}`;
  }



  async health(): Promise<{ status: string; app: string; version: string }> {

    const res = await fetch(this.url("/api/health"));

    return res.json();

  }



  async getNodes(): Promise<NodeItem[]> {

    const res = await fetch(this.url("/api/nodes"), { headers: this.headers });

    if (!res.ok) throw new Error("获取节点失败");

    return res.json();

  }



  async importProfiles(): Promise<{ imported: number; errors: number }> {

    const res = await fetch(this.url("/api/nodes/import"), {

      method: "POST",

      headers: this.headers,

    });

    if (!res.ok) throw new Error("导入配置文件失败");

    return res.json();

  }



  async openProfilesFolder(): Promise<void> {

    await fetch(this.url("/api/nodes/open-folder"), {

      method: "POST",

      headers: this.headers,

    });

  }



  async getRecentNodes(): Promise<string[]> {

    try {

      const res = await fetch(this.url("/api/nodes/recent"), { headers: this.headers });

      if (res.ok) {

        const data = await res.json();

        return Array.isArray(data) ? data : [];

      }

    } catch {}

    return [];

  }



  async setRecentNodes(nodeIds: string[]): Promise<void> {

    try {

      await fetch(this.url("/api/nodes/recent"), {

        method: "POST",

        headers: this.headers,

        body: JSON.stringify({ node_ids: nodeIds }),

      });

    } catch {}

  }



  async startProbing(): Promise<{ status: string }> {

    const res = await fetch(this.url("/api/probe/start"), {

      method: "POST",

      headers: this.headers,

    });

    return res.json();

  }



  async stopProbing(): Promise<{ status: string }> {

    const res = await fetch(this.url("/api/probe/stop"), {

      method: "POST",

      headers: this.headers,

    });

    return res.json();

  }



  async getVpnStatus(): Promise<VPNStatus> {

    const res = await fetch(this.url(`/api/vpn/status?_=${Date.now()}`), { headers: { ...this.headers, "Cache-Control": "no-cache", Pragma: "no-cache" }, cache: "no-store" });

    if (!res.ok) throw new Error("获取 VPN 状态失败");

    return res.json();

  }



  async getTraffic(): Promise<TrafficData> {

    const res = await fetch(this.url("/api/vpn/traffic"), { headers: this.headers });

    if (!res.ok) return { uploadSpeedBps: 0, downloadSpeedBps: 0 };

    return res.json();

  }



  async connectVPN(nodeId: string, mode: "global" | "split" = "split"): Promise<{ status?: string; error?: string }> {
    const res = await fetch(this.url("/api/vpn/connect"), {
      method: "POST",
      headers: this.headers,
      body: JSON.stringify({ node_id: nodeId, nodeId, mode }),
    });
    return res.json();
  }



  async disconnectVPN(): Promise<{ status: string }> {

    const res = await fetch(this.url("/api/vpn/disconnect"), {

      method: "POST",

      headers: this.headers,

    });

    return res.json();

  }



  async getCredentials(): Promise<{ hasCredentials: boolean; username: string }> {

    const res = await fetch(this.url("/api/credentials"), { headers: this.headers });

    return res.json();

  }



  async saveCredentials(username: string, password: string): Promise<void> {

    const res = await fetch(this.url("/api/credentials"), {

      method: "POST",

      headers: this.headers,

      body: JSON.stringify({ username, password, persistent: true }),

    });

    if (!res.ok) throw new Error("保存凭据失败");

  }



  async clearCredentials(): Promise<void> {

    await fetch(this.url("/api/credentials"), {

      method: "DELETE",

      headers: this.headers,

    });

  }



  async getRoutingRules(): Promise<RoutingRule[]> {

    const res = await fetch(this.url("/api/routing/rules"), { headers: this.headers });

    return res.json();

  }



  async getInstalledApps(): Promise<InstalledApp[]> {

    const res = await fetch(this.url("/api/routing/installed-apps"), { headers: this.headers });

    return res.json();

  }



  async setRoutingRule(

    executablePath: string,

    appName: string,

    action: "VPN" | "DIRECT",

    enabled: boolean

  ): Promise<{ ok?: boolean; error?: string }> {

    const res = await fetch(this.url("/api/routing/rule"), {

      method: "POST",

      headers: this.headers,

      body: JSON.stringify({

        executable_path: executablePath,

        app_name: appName,

        action,

        enabled,

      }),

    });

    return res.json();

  }



  async deleteRoutingRule(executablePath: string): Promise<void> {

    await fetch(

      `${this.url("/api/routing/rule")}?executable_path=${encodeURIComponent(executablePath)}`,

      {

        method: "DELETE",

        headers: this.headers,

      }

    );

  }



  async startRouting(): Promise<{ ok?: boolean; error?: string }> {

    const res = await fetch(this.url("/api/routing/start"), {

      method: "POST",

      headers: this.headers,

    });

    return res.json();

  }



  async stopRouting(): Promise<{ ok?: boolean }> {

    const res = await fetch(this.url("/api/routing/stop"), {

      method: "POST",

      headers: this.headers,

    });

    return res.json();

  }



  async getLogs(): Promise<string[]> {

    const res = await fetch(this.url("/api/logs"), { headers: this.headers });

    const data = await res.json();

    return Array.isArray(data.logs) ? data.logs : [];

  }



  async clearLogs(): Promise<void> {

    await fetch(this.url("/api/logs"), {

      method: "DELETE",

      headers: this.headers,

    });

  }



  async uninstallSystem(): Promise<void> {

    await fetch(this.url("/api/system/uninstall"), {

      method: "POST",

      headers: this.headers,

    });

  }



  async repairOpenVPN(): Promise<{ ok?: boolean; error?: string }> {

    const res = await fetch(this.url("/api/openvpn/install"), {

      method: "POST",

      headers: this.headers,

    });

    return res.json();

  }



  async getOpenVPNInstallStatus(): Promise<{ state: string; message: string; percentage?: number; code?: string }> {

    const res = await fetch(this.url("/api/openvpn/install-status"), { headers: this.headers });

    return res.json();

  }

}
