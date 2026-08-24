export type RoutingAction = "VPN" | "DIRECT";



export interface RoutingRule {

  ruleId: string;

  appName: string;

  executablePath: string;

  action: RoutingAction;

  isEnabled: boolean;

}



export interface InstalledApp {

  appName: string;

  executablePath: string;

  publisher?: string;

  version?: string;

}



export interface NodeItem {

  nodeId: string;

  serverName: string;

  country: string;

  city: string;

  overallScore: number;

  webScore: number;

  videoScore: number;

  stabilityScore: number;

  bestTcpLatency: number | null;

  isReachable: boolean;

  explanation: string;

  protocol: string;

  port: number;

  lastMeasuredAt: number | null;

}



export interface ProbeProgressData {

  total: number;

  completed: number;

  percentage: number;

  currentNode: string;

  stage: string;

}



export interface NetworkSnapshot {

  direct_ip?: string;

  vpn_ip?: string;

  direct_dns?: string[];

  vpn_dns?: string[];

  direct_interface?: string;

  vpn_interface?: string;

}



export interface VPNStatus {

  isConnected: boolean;

  code?: string;

  state: string;

  connectedNodeId: string | null;

  runtimeDisplayName?: string;

  runtimeReady?: boolean;

  driverReady?: boolean;

  mode?: "global" | "split";

  isRoutingRunning: boolean;

  hasCredentials: boolean;

  snapshot?: NetworkSnapshot;

}



export interface TrafficData {

  uploadSpeedBps: number;

  downloadSpeedBps: number;

  bytesIn?: number;

  bytesOut?: number;

}



export type ToastType = "success" | "error" | "info" | "warning";



export interface ToastMessage {

  id: string;

  type: ToastType;

  title: string;

  description?: string;

}
