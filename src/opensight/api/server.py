import asyncio

import json

import os

import subprocess

import sys

import threading

from typing import List, Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, HTTPException, status, Query

from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel



from opensight.core.constants import APP_VERSION, APP_NAME

from opensight.core.database import DatabaseManager, Repository

from opensight.core.importer import ProfileImporter

from opensight.core.models import RoutingRule

from opensight.core.probe_engine import SafeProbeEngine

from opensight.core.recommendation import RecommendationEngine

from opensight.core.safety import PortablePaths, is_reparse_point_or_symlink, validate_subpath

from opensight.core.settings import AppSettings

from opensight.vpn.credentials import CredentialVault

from opensight.vpn.detector import OpenVPNDetector

from opensight.vpn.openvpn_process import OpenVPNProcessManager

from opensight.vpn.routing.app_selector import AppSelector

from opensight.vpn.routing.singbox_backend import SingBoxRoutingBackend



class CredentialsPayload(BaseModel):

    username: str

    password: str

    persistent: bool = True



class RulePayload(BaseModel):

    executable_path: str

    app_name: str

    action: str

    enabled: bool



class ConnectPayload(BaseModel):

    node_id: str

    mode: str = "global"



class RecentNodesPayload(BaseModel):

    node_ids: List[str]



import secrets

security_scheme = HTTPBearer(auto_error=False)

def create_app(paths: PortablePaths, auth_token: str = "", allow_insecure: bool = False) -> FastAPI:
    app = FastAPI(title="OpenSight Core API", docs_url=None, redoc_url=None)

    # 生产模式下若未显式传入且未启用非安全模式，自动生成 256-bit 熵高强度 Token
    if not auth_token and not allow_insecure:
        auth_token = secrets.token_hex(32)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["tauri://localhost", "http://localhost", "http://127.0.0.1", "http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Requested-With", "Accept"],
    )

    db = DatabaseManager(paths.data_dir / "opensight.db")
    repo = Repository(db)
    rec_engine = RecommendationEngine(repo)
    vpn_detector = OpenVPNDetector(paths)
    vault = CredentialVault(paths)
    vpn_mgr = OpenVPNProcessManager(paths)
    routing_backend = SingBoxRoutingBackend(paths)
    settings = AppSettings.load_from_repository(repo)

    active_probe_engine: Optional[SafeProbeEngine] = None
    active_probe_loop: Optional[asyncio.AbstractEventLoop] = None
    probe_engine_lock = threading.Lock()
    _routing_lock = threading.RLock()

    def verify_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme)):
        if allow_insecure and not auth_token:
            return True
        if not credentials or not credentials.credentials or credentials.credentials != auth_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="未授权访问: 需要有效的 Bearer Token",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return True

    ws_clients: List[WebSocket] = []

    async def broadcast_ws(event: str, data: dict):
        dead_clients = []
        for ws in ws_clients:
            try:
                await ws.send_json({"event": event, "data": data})
            except Exception:
                dead_clients.append(ws)
        for dead in dead_clients:
            if dead in ws_clients:
                ws_clients.remove(dead)

    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket, token: Optional[str] = Query(None)):
        if not allow_insecure or auth_token:
            if not token or token != auth_token:
                await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
                return
        await websocket.accept()
        ws_clients.append(websocket)

        try:

            while True:

                await websocket.receive_text()

        except WebSocketDisconnect:

            if websocket in ws_clients:

                ws_clients.remove(websocket)



    @app.get("/api/health")

    def health():

        return {"status": "ok", "app": APP_NAME, "version": APP_VERSION}



    @app.get("/api/nodes", dependencies=[Depends(verify_token)])

    def get_nodes(mode: str = "综合推荐"):

        recs = rec_engine.evaluate_all_nodes()

        sorted_recs = rec_engine.sort_recommendations(recs, mode)

        return [

            {

                "nodeId": r.node_id,

                "serverName": r.server_name,

                "country": r.country,

                "city": r.city,

                "overallScore": r.overall_score,

                "webScore": r.web_score,

                "videoScore": r.video_score,

                "stabilityScore": r.stability_score,

                "bestTcpLatency": r.best_tcp_latency_ms,

                "isReachable": r.is_reachable,

                "explanation": r.explanation,

                "protocol": r.primary_protocol,

                "port": r.primary_port,

                "lastMeasuredAt": r.last_measured_at,

            }

            for r in sorted_recs

        ]



    @app.post("/api/nodes/import", dependencies=[Depends(verify_token)])

    def import_profiles():

        rep = ProfileImporter.import_from_directory(paths.profiles_dir)

        if rep.imported_count:

            repo.sync_batch_profiles(list(rep.profiles))

        return {"imported": rep.imported_count, "errors": rep.error_count}



    @app.get("/api/nodes/recent", dependencies=[Depends(verify_token)])

    def get_recent_nodes():

        return repo.get_recent_nodes()



    @app.post("/api/nodes/recent", dependencies=[Depends(verify_token)])

    def save_recent_nodes(payload: RecentNodesPayload):

        repo.set_recent_nodes(payload.node_ids)

        return {"ok": True, "count": len(payload.node_ids)}



    @app.post("/api/nodes/open-folder", dependencies=[Depends(verify_token)])

    def open_profiles_folder():

        p = paths.profiles_dir

        if is_reparse_point_or_symlink(p):

            raise HTTPException(status_code=400, detail="安全违规: 配置目录被重定向或为符号链接")

        validate_subpath(paths.base_dir, p)

        if sys.platform == "win32" and p.exists():

            os.startfile(str(p))

        return {"ok": True}



    @app.post("/api/probe/start", dependencies=[Depends(verify_token)])

    def start_probing():

        nonlocal active_probe_engine

        nodes = repo.get_all_nodes()

        with probe_engine_lock:

            if active_probe_engine is not None and not active_probe_engine.is_stopped:

                return {"status": "already_running"}

            engine = SafeProbeEngine(repo, settings.probe_concurrency)

            active_probe_engine = engine



        def run():

            nonlocal active_probe_engine, active_probe_loop

            loop = asyncio.new_event_loop()

            asyncio.set_event_loop(loop)

            with probe_engine_lock:

                active_probe_loop = loop



            def on_progress(p):

                asyncio.run_coroutine_threadsafe(

                    broadcast_ws("probe_progress", {

                        "total": p.total,

                        "completed": p.completed,

                        "percentage": p.percentage,

                        "currentNode": p.current_node_name,

                        "stage": p.current_stage

                    }),

                    loop

                )



            try:

                loop.run_until_complete(engine.run_batch(nodes, on_progress, False))

            finally:

                try:

                    loop.run_until_complete(broadcast_ws("probe_finished", {"stopped": engine.is_stopped}))

                finally:

                    with probe_engine_lock:

                        if active_probe_engine is engine:

                            active_probe_engine = None

                            active_probe_loop = None

                    loop.close()



        threading.Thread(target=run, daemon=True).start()

        return {"status": "started"}



    @app.post("/api/probe/stop", dependencies=[Depends(verify_token)])

    def stop_probing():

        with probe_engine_lock:

            engine = active_probe_engine

            loop = active_probe_loop

        if engine is None:

            return {"status": "not_running"}

        if loop is not None and loop.is_running():

            loop.call_soon_threadsafe(engine.stop)

        else:

            engine.stop()

        return {"status": "stopping"}



    @app.get("/api/vpn/status", dependencies=[Depends(verify_token)])

    def get_vpn_status():

        runtime = vpn_detector.resolve_best_runtime()
        if vpn_mgr.is_connected():
            vpn_mgr.refresh_network_snapshot()
        return {
            "isConnected": vpn_mgr.is_connected(),
            "state": vpn_mgr.get_state(),
            "connectedNodeId": vpn_mgr.connected_node_id,
            "runtimeDisplayName": runtime.display_name,
            "runtimeReady": runtime.is_valid,
            "driverReady": vpn_detector.detect_driver_ready(),
            "mode": vpn_mgr.routing_mode,
            "isRoutingRunning": routing_backend.is_running(),
            "hasCredentials": vault.load_credentials() is not None,
            "snapshot": vpn_mgr.get_network_snapshot() if vpn_mgr.is_connected() else {},
        }



    @app.get("/api/vpn/traffic", dependencies=[Depends(verify_token)])

    def get_vpn_traffic():

        return vpn_mgr.get_traffic_rates()



    @app.post("/api/vpn/connect", dependencies=[Depends(verify_token)])

    def connect_vpn(payload: ConnectPayload):
        node_id = payload.node_id
        if payload.mode not in {"global", "split"}:
            return {"error": "连接模式无效"}
        if vpn_mgr.is_connected() or vpn_mgr.get_state() in {"CONNECTING", "STARTING", "VALIDATING", "AUTHENTICATING", "DISCONNECTING"}:
            return {"error": "当前已有 VPN 连接，请先断开后再切换节点"}

        nodes = [n for n in repo.get_all_nodes() if n.node_id == node_id]

        endpoints = repo.get_endpoints_for_node(node_id)

        if not nodes or not endpoints:

            return {"error": "节点端点不存在"}

        credentials = vault.load_credentials()

        if not credentials:

            return {"error": "请先保存 VPN 凭据"}

        runtime = vpn_detector.resolve_best_runtime()

        if not runtime.is_valid:

            return {"error": "OpenVPN 官方组件未就绪"}

        profiles = repo.get_all_profiles()

        profile = next((p for p in profiles if p.profile_id == endpoints[0].profile_id), None)

        if not profile:

            return {"error": "未找到关联的配置文件"}



        # 从数据库加载启用的 VPN 规则并配置 KillSwitch

        with repo._db.transaction() as conn:

            vpn_rules = conn.execute(

                "SELECT executable_path FROM routing_rules WHERE is_enabled = 1 AND action = 'VPN';"

            ).fetchall()

            vpn_mgr.configure_kill_switch([r["executable_path"] for r in vpn_rules])



        profile_path = paths.profiles_dir / profile.relative_path



        def callback(code: str, message: str):

            asyncio.run(broadcast_ws("vpn_state_change", {"code": code, "message": message}))



        threading.Thread(

            target=vpn_mgr.connect,

            kwargs={

                "node": nodes[0],

                "endpoint": endpoints[0],

                "profile_path": str(profile_path),

                "credentials": credentials,

                "executable_path": runtime.executable_path,

                "routing_mode": payload.mode,

                "on_state_change": callback,

            },

            daemon=True,

        ).start()

        return {"status": "connecting"}



    @app.post("/api/vpn/disconnect", dependencies=[Depends(verify_token)])

    def disconnect_vpn():
        if routing_backend.is_running():
            routing_backend.stop_routing()
        threading.Thread(target=vpn_mgr.disconnect, daemon=True).start()
        return {"status": "disconnecting"}



    @app.get("/api/credentials", dependencies=[Depends(verify_token)])

    def get_credentials():

        c = vault.load_credentials()

        return {"hasCredentials": c is not None, "username": c.username if c else ""}



    @app.post("/api/credentials", dependencies=[Depends(verify_token)])

    def save_credentials(payload: CredentialsPayload):

        if payload.persistent:

            vault.save_persistent_credentials(payload.username, payload.password)

        else:

            vault.set_session_credentials(payload.username, payload.password)

        return {"ok": True}



    @app.delete("/api/credentials", dependencies=[Depends(verify_token)])

    def clear_credentials():

        vault.clear_saved_credentials()

        return {"ok": True}



    @app.get("/api/routing/rules", dependencies=[Depends(verify_token)])

    def get_routing_rules():

        with repo._db.transaction() as conn:

            rules = [

                {

                    "ruleId": row["rule_id"],

                    "appName": row["app_name"],

                    "executablePath": row["executable_path"],

                    "action": row["action"],

                    "isEnabled": bool(row["is_enabled"])

                }

                for row in conn.execute("SELECT * FROM routing_rules ORDER BY app_name;").fetchall()

            ]

        return rules



    @app.get("/api/routing/installed-apps", dependencies=[Depends(verify_token)])

    def get_installed_apps():

        return [

            {

                "appName": app.app_name,

                "executablePath": app.executable_path,

                "publisher": app.publisher,

                "version": app.version,

            }

            for app in AppSelector.list_installed_applications()

        ]



    @app.post("/api/routing/rule", dependencies=[Depends(verify_token)])

    def set_routing_rule(payload: RulePayload):

        validated = AppSelector.validate_executable(payload.executable_path, payload.app_name)

        if not validated.is_valid:

            return {"ok": False, "error": validated.rejection_reason}

        import hashlib

        rule_id = "r_" + hashlib.sha256(validated.executable_path.lower().encode("utf-8")).hexdigest()[:16]

        action = "VPN" if payload.action == "VPN" else "DIRECT"



        with _routing_lock:

            # 1. 查询当前已存在的 VPN 规则集合

            with repo._db.transaction() as conn:

                old_vpn_rows = conn.execute(

                    "SELECT executable_path FROM routing_rules WHERE is_enabled = 1 AND action = 'VPN';"

                ).fetchall()

                old_vpn_exes = [r["executable_path"] for r in old_vpn_rows]



            # 2. 计算新状态期望的 VPN 规则集合

            target_norm = validated.executable_path.strip().lower()

            is_vpn_target = (action == "VPN" and payload.enabled)

            filtered_exes = [x for x in old_vpn_exes if x.strip().lower() != target_norm]

            new_vpn_exes = filtered_exes + ([validated.executable_path] if is_vpn_target else [])



            # 3. 若已连接 VPN，执行两阶段补偿同步事务

            if vpn_mgr.is_connected():

                if not vpn_mgr.sync_kill_switch(new_vpn_exes):

                    return {"ok": False, "error": "KillSwitch 防火墙规则同步失败，已恢复原防火墙状态"}

                try:

                    with repo._db.transaction() as conn:

                        conn.execute(

                            "INSERT INTO routing_rules VALUES (?, ?, ?, ?, ?, strftime('%s','now')) "

                            "ON CONFLICT(executable_path) DO UPDATE SET "

                            "app_name=excluded.app_name, action=excluded.action, is_enabled=excluded.is_enabled;",

                            (rule_id, validated.app_name, validated.executable_path, action, 1 if payload.enabled else 0),

                        )

                except Exception as db_err:

                    # 数据库提交失败：触发补偿事务，恢复旧防火墙状态

                    comp_ok = vpn_mgr.sync_kill_switch(old_vpn_exes)

                    if not comp_ok:

                        return {"ok": False, "error": f"数据库写入失败且防火墙回滚失败: {db_err}"}

                    return {"ok": False, "error": f"数据库写入失败，已恢复防火墙状态: {db_err}"}

            else:

                try:

                    with repo._db.transaction() as conn:

                        conn.execute(

                            "INSERT INTO routing_rules VALUES (?, ?, ?, ?, ?, strftime('%s','now')) "

                            "ON CONFLICT(executable_path) DO UPDATE SET "

                            "app_name=excluded.app_name, action=excluded.action, is_enabled=excluded.is_enabled;",

                            (rule_id, validated.app_name, validated.executable_path, action, 1 if payload.enabled else 0),

                        )

                except Exception as db_err:

                    return {"ok": False, "error": f"数据库写入失败: {db_err}"}



        return {"ok": True}



    @app.delete("/api/routing/rule", dependencies=[Depends(verify_token)])

    def delete_routing_rule(executable_path: str):

        with _routing_lock:

            # 1. 查询当前已存在的 VPN 规则集合

            with repo._db.transaction() as conn:

                old_vpn_rows = conn.execute(

                    "SELECT executable_path FROM routing_rules WHERE is_enabled = 1 AND action = 'VPN';"

                ).fetchall()

                old_vpn_exes = [r["executable_path"] for r in old_vpn_rows]



            # 2. 计算删除后的期望 VPN 规则集合

            target_norm = executable_path.strip().lower()

            new_vpn_exes = [x for x in old_vpn_exes if x.strip().lower() != target_norm]



            # 3. 若已连接 VPN，执行两阶段补偿同步事务

            if vpn_mgr.is_connected():

                if not vpn_mgr.sync_kill_switch(new_vpn_exes):

                    return {"ok": False, "error": "KillSwitch 防火墙规则同步失败，已恢复原防火墙状态"}

                try:

                    with repo._db.transaction() as conn:

                        conn.execute("DELETE FROM routing_rules WHERE executable_path = ?;", (executable_path,))

                except Exception as db_err:

                    # 数据库删除失败：触发补偿事务，恢复旧防火墙状态

                    comp_ok = vpn_mgr.sync_kill_switch(old_vpn_exes)

                    if not comp_ok:

                        return {"ok": False, "error": f"数据库删除失败且防火墙回滚失败: {db_err}"}

                    return {"ok": False, "error": f"数据库删除失败，已恢复防火墙状态: {db_err}"}

            else:

                try:

                    with repo._db.transaction() as conn:

                        conn.execute("DELETE FROM routing_rules WHERE executable_path = ?;", (executable_path,))

                except Exception as db_err:

                    return {"ok": False, "error": f"数据库删除失败: {db_err}"}



        return {"ok": True}



    @app.post("/api/routing/start", dependencies=[Depends(verify_token)])

    def start_routing():

        if not vpn_mgr.is_connected():

            return {"error": "请先连接 VPN 隧道后再启用应用分流"}

        with repo._db.transaction() as conn:

            rules = [

                RoutingRule(row["rule_id"], row["app_name"], row["executable_path"], row["action"], bool(row["is_enabled"]))

                for row in conn.execute("SELECT * FROM routing_rules WHERE is_enabled = 1;").fetchall()

            ]

        snapshot = vpn_mgr.get_network_snapshot()

        ok = routing_backend.start_routing(

            rules=rules,

            direct_dns=snapshot.get("direct_dns", []),

            vpn_dns=snapshot.get("vpn_dns", []),

            direct_interface=snapshot.get("direct_interface"),

            vpn_interface=snapshot.get("vpn_interface"),

        )

        if ok:

            vpn_mgr._leak_guard.enable_split_dns_mode()

        return {"ok": ok, "state": routing_backend.get_state()}



    @app.post("/api/routing/stop", dependencies=[Depends(verify_token)])

    def stop_routing():

        ok = routing_backend.stop_routing()

        if ok:

            vpn_mgr._leak_guard.disable_split_dns_mode()

        return {"ok": ok, "state": routing_backend.get_state()}



    @app.get("/api/logs", dependencies=[Depends(verify_token)])

    def get_logs():

        log_file = paths.logs_dir / "opensight.log"

        if log_file.exists():

            return {"logs": log_file.read_text(encoding="utf-8", errors="ignore").splitlines()[-200:]}

        return {"logs": []}



    @app.delete("/api/logs", dependencies=[Depends(verify_token)])

    def clear_logs():

        log_file = paths.logs_dir / "opensight.log"

        if log_file.exists():

            log_file.write_text("", encoding="utf-8")

        return {"ok": True}



    @app.post("/api/system/uninstall", dependencies=[Depends(verify_token)])

    def run_full_uninstall():

        helper = paths.base_dir / "uninstall_opensight_windows.ps1"

        if not helper.is_file():

            return {"error": "未找到卸载辅助脚本"}

        subprocess.Popen(

            [

                "powershell.exe",

                "-NoProfile",

                "-WindowStyle",

                "Hidden",

                "-ExecutionPolicy",

                "Bypass",

                "-File",

                str(helper),

                "-BundleRoot",

                str(paths.base_dir)

            ],

            cwd=str(paths.base_dir),

            shell=False

        )

        return {"ok": True}



    @app.get("/api/openvpn/install-status", dependencies=[Depends(verify_token)])

    def get_openvpn_install_status():

        status_file = paths.data_dir / "repair_status.json"

        if status_file.is_file():

            try:

                return json.loads(status_file.read_text(encoding="utf-8"))

            except Exception:

                pass

        return {"state": "idle", "message": "就绪"}



    @app.post("/api/openvpn/install", dependencies=[Depends(verify_token)])

    def install_openvpn():

        if vpn_mgr.is_connected() or routing_backend.is_running():
            return {"error": "请先断开 VPN 并停止应用分流，再修复驱动"}

        helper = paths.base_dir / "repair_openvpn_windows.ps1"

        if not helper.is_file():

            return {"error": "未找到安装辅助脚本"}

        status_file = paths.data_dir / "repair_status.json"

        try:

            init_payload = json.dumps(

                {"state": "starting", "message": "正在准备安装...", "percentage": 5},

                ensure_ascii=False,

            )

            status_file.write_text(init_payload, encoding="utf-8")

        except Exception:

            pass

        subprocess.Popen(

            [

                "powershell.exe",

                "-NoProfile",

                "-WindowStyle",

                "Hidden",

                "-ExecutionPolicy",

                "Bypass",

                "-File",

                str(helper),

                "-StatusFile",

                str(status_file)

            ],

            cwd=str(paths.base_dir),

            shell=False

        )

        return {"ok": True}



    return app
