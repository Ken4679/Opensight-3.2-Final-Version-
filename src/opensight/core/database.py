import atexit
import sqlite3
import threading
import time
from pathlib import Path
from typing import Optional, List, Tuple
from contextlib import contextmanager
from opensight.core.models import ProfileMetadata, LogicalNode, Endpoint, MeasurementRecord, ParsedProfile

class DatabaseError(Exception):
    pass

class DatabaseManager:
    def __init__(self, db_path: Path):
        self._db_path = db_path.resolve()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), timeout=15.0)
        conn.row_factory = sqlite3.Row
        # 高性能 SQLite PRAGMA 配置
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA cache_size = -64000;")
        conn.execute("PRAGMA temp_store = MEMORY;")
        conn.execute("PRAGMA mmap_size = 268435456;")
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn

    @contextmanager
    def transaction(self):
        conn = self.get_connection()
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise DatabaseError(str(e)) from e
        finally:
            conn.close()

    def _init_db(self):
        with self.transaction() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at INTEGER);")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS profiles (
                    profile_id TEXT PRIMARY KEY, filename TEXT NOT NULL, relative_path TEXT NOT NULL UNIQUE,
                    file_sha256 TEXT NOT NULL, file_size_bytes INTEGER NOT NULL, provider TEXT DEFAULT 'ProtonVPN',
                    imported_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nodes (
                    node_id TEXT PRIMARY KEY, provider TEXT NOT NULL, server_name TEXT NOT NULL,
                    country TEXT NOT NULL, country_code TEXT NOT NULL, city TEXT NOT NULL,
                    is_free_tier INTEGER DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS endpoints (
                    endpoint_id TEXT PRIMARY KEY, node_id TEXT NOT NULL, profile_id TEXT NOT NULL,
                    protocol TEXT NOT NULL, host TEXT NOT NULL, ip_resolved TEXT, port INTEGER NOT NULL,
                    is_active INTEGER DEFAULT 1, last_measured_at INTEGER,
                    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE,
                    FOREIGN KEY (profile_id) REFERENCES profiles(profile_id) ON DELETE CASCADE,
                    UNIQUE(node_id, protocol, host, port)
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS measurements (
                    measurement_id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL, node_id TEXT NOT NULL,
                    measured_at INTEGER NOT NULL, dns_latency_ms REAL, tcp_latency_ms REAL,
                    direct_https_latency_ms REAL, packet_loss_pct REAL DEFAULT 0.0, jitter_ms REAL DEFAULT 0.0,
                    is_reachable INTEGER NOT NULL, error_message TEXT, web_score REAL DEFAULT 0.0,
                    video_score REAL DEFAULT 0.0, stability_score REAL DEFAULT 0.0, overall_score REAL DEFAULT 0.0,
                    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id) ON DELETE CASCADE,
                    FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER NOT NULL
                );
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS routing_rules (
                    rule_id TEXT PRIMARY KEY, app_name TEXT NOT NULL, executable_path TEXT NOT NULL UNIQUE,
                    action TEXT NOT NULL, is_enabled INTEGER DEFAULT 1, created_at INTEGER NOT NULL
                );
            """)
            # 性能加速索引
            conn.execute("CREATE INDEX IF NOT EXISTS idx_endpoints_node ON endpoints(node_id);")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_measurements_ep_time ON measurements(endpoint_id, measured_at DESC);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_measurements_node_time ON measurements(node_id, measured_at DESC);"
            )

class Repository:
    def __init__(self, db_manager: DatabaseManager):
        self._db = db_manager
        self._queue_lock = threading.Lock()
        self._pending_measurements: List[MeasurementRecord] = []
        self._last_flush_time = time.time()
        self._flush_timer: Optional[threading.Timer] = None
        atexit.register(self._flush_pending)

    def _flush_pending(self) -> None:
        """内部攒批安全刷盘机制（线程安全与异常强隔离）"""
        with self._queue_lock:
            if self._flush_timer:
                try:
                    self._flush_timer.cancel()
                except Exception:
                    pass
                self._flush_timer = None
            if not self._pending_measurements:
                return
            batch = self._pending_measurements
            self._pending_measurements = []
            self._last_flush_time = time.time()

        try:
            m_params = [
                (
                    m.measurement_id, m.endpoint_id, m.node_id, m.measured_at,
                    m.dns_latency_ms, m.tcp_latency_ms, m.direct_https_latency_ms,
                    m.packet_loss_pct, m.jitter_ms, 1 if m.is_reachable else 0,
                    m.error_message, m.web_score, m.video_score, m.stability_score, m.overall_score
                )
                for m in batch
            ]
            ep_params = [(m.measured_at, m.endpoint_id) for m in batch]
            with self._db.transaction() as conn:
                conn.executemany(
                    "INSERT INTO measurements VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                    m_params,
                )
                conn.executemany("UPDATE endpoints SET last_measured_at = ? WHERE endpoint_id = ?;", ep_params)
        except Exception:
            pass

    def record_measurement(self, m: MeasurementRecord) -> None:
        """记录测速结果：内部累积 10 条或 1 秒超时自动批量写入"""
        should_flush = False
        with self._queue_lock:
            self._pending_measurements.append(m)
            if len(self._pending_measurements) >= 10 or (time.time() - self._last_flush_time >= 1.0):
                should_flush = True
            elif self._flush_timer is None:
                self._flush_timer = threading.Timer(1.0, self._flush_pending)
                self._flush_timer.daemon = True
                self._flush_timer.start()
        if should_flush:
            self._flush_pending()

    def sync_parsed_profile(self, parsed: ParsedProfile) -> Tuple[LogicalNode, List[Endpoint]]:
        self._flush_pending()
        now = int(time.time())
        with self._db.transaction() as conn:
            existing = conn.execute(
                "SELECT profile_id FROM profiles WHERE relative_path = ?;",
                (parsed.relative_path,),
            ).fetchone()
            if existing and existing["profile_id"] != parsed.profile_id:
                conn.execute("DELETE FROM profiles WHERE relative_path = ?;", (parsed.relative_path,))

            conn.execute("""
                INSERT INTO profiles (
                    profile_id, filename, relative_path, file_sha256,
                    file_size_bytes, provider, imported_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(relative_path) DO UPDATE SET 
                    profile_id = excluded.profile_id,
                    filename = excluded.filename,
                    file_sha256 = excluded.file_sha256,
                    file_size_bytes = excluded.file_size_bytes,
                    updated_at = excluded.updated_at;
            """, (
                parsed.profile_id, parsed.filename, parsed.relative_path,
                parsed.file_sha256, parsed.file_size_bytes, parsed.provider, now, now
            ))

            node_id = LogicalNode.compute_id(parsed.provider, parsed.country_code, parsed.city, parsed.server_name)
            conn.execute("""
                INSERT INTO nodes (
                    node_id, provider, server_name, country,
                    country_code, city, is_free_tier, created_at, updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(node_id) DO UPDATE SET updated_at = excluded.updated_at;
            """, (
                node_id, parsed.provider, LogicalNode.normalize_server_name(parsed.server_name),
                parsed.country, parsed.country_code.upper(), parsed.city,
                1 if parsed.is_free_tier else 0, now, now
            ))
            node = LogicalNode(
                node_id, parsed.provider, LogicalNode.normalize_server_name(parsed.server_name),
                parsed.country, parsed.country_code.upper(), parsed.city, parsed.is_free_tier, now, now
            )

            endpoints = []
            ep_records = []
            for r in parsed.remotes:
                norm_host = Endpoint.normalize_host(r.host)
                eid = Endpoint.compute_id(node_id, r.protocol, norm_host, r.port)
                ep_records.append((eid, node_id, parsed.profile_id, r.protocol, norm_host, r.port))
                endpoints.append(Endpoint(eid, node_id, parsed.profile_id, r.protocol, norm_host, r.port))

            conn.executemany("""
                INSERT INTO endpoints (endpoint_id, node_id, profile_id, protocol, host, port, is_active)
                VALUES (?, ?, ?, ?, ?, ?, 1)
                ON CONFLICT(node_id, protocol, host, port) DO UPDATE SET profile_id = excluded.profile_id, is_active = 1;
            """, ep_records)
            return node, endpoints

    def sync_batch_profiles(self, profiles: List[ParsedProfile]) -> int:
        for p in profiles:
            self.sync_parsed_profile(p)
        return len(profiles)

    def get_all_nodes(self) -> List[LogicalNode]:
        with self._db.transaction() as conn:
            rows = conn.execute("SELECT * FROM nodes ORDER BY country ASC, server_name ASC;").fetchall()
            return [
                LogicalNode(
                    r["node_id"], r["provider"], r["server_name"], r["country"],
                    r["country_code"], r["city"], bool(r["is_free_tier"]), r["created_at"], r["updated_at"]
                )
                for r in rows
            ]

    def get_endpoints_for_node(self, node_id: str) -> List[Endpoint]:
        with self._db.transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM endpoints WHERE node_id = ? ORDER BY protocol ASC, port ASC;",
                (node_id,),
            ).fetchall()
            return [
                Endpoint(
                    r["endpoint_id"], r["node_id"], r["profile_id"], r["protocol"],
                    r["host"], r["ip_resolved"], r["port"], bool(r["is_active"]), r["last_measured_at"]
                )
                for r in rows
            ]

    def get_all_profiles(self) -> List[ProfileMetadata]:
        with self._db.transaction() as conn:
            rows = conn.execute("SELECT * FROM profiles;").fetchall()
            return [
                ProfileMetadata(
                    r["profile_id"], r["filename"], r["relative_path"], r["file_sha256"],
                    r["file_size_bytes"], r["provider"], r["imported_at"], r["updated_at"]
                )
                for r in rows
            ]

    def set_endpoint_ip(self, endpoint_id: str, ip: Optional[str]) -> None:
        with self._db.transaction() as conn:
            conn.execute("UPDATE endpoints SET ip_resolved = ? WHERE endpoint_id = ?;", (ip, endpoint_id))

    def get_latest_measurement_for_endpoint(self, endpoint_id: str) -> Optional[MeasurementRecord]:
        self._flush_pending()
        with self._db.transaction() as conn:
            r = conn.execute(
                "SELECT * FROM measurements WHERE endpoint_id = ? ORDER BY measured_at DESC LIMIT 1;",
                (endpoint_id,),
            ).fetchone()
            return self._row_to_m(r) if r else None

    def get_latest_measurement_for_node(self, node_id: str) -> Optional[MeasurementRecord]:
        self._flush_pending()
        with self._db.transaction() as conn:
            r = conn.execute(
                "SELECT * FROM measurements WHERE node_id = ? ORDER BY measured_at DESC LIMIT 1;",
                (node_id,),
            ).fetchone()
            return self._row_to_m(r) if r else None

    def get_measurement_history_for_node(self, node_id: str, limit: int = 10) -> List[MeasurementRecord]:
        self._flush_pending()
        with self._db.transaction() as conn:
            rows = conn.execute(
                "SELECT * FROM measurements WHERE node_id = ? ORDER BY measured_at DESC LIMIT ?;",
                (node_id, limit),
            ).fetchall()
            return [self._row_to_m(r) for r in rows]

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        with self._db.transaction() as conn:
            r = conn.execute("SELECT value FROM settings WHERE key = ?;", (key,)).fetchone()
            return r["value"] if r else default

    def set_setting(self, key: str, value: str) -> None:
        with self._db.transaction() as conn:
            conn.execute("""
                INSERT INTO settings VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
            """, (key, str(value), int(time.time())))

    def get_recent_nodes(self) -> List[str]:
        """获取最近使用过的节点 ID 列表"""
        val = self.get_setting("recent_nodes_json", "[]")
        try:
            import json
            data = json.loads(val or "[]")
            if isinstance(data, list):
                return [str(x) for x in data if isinstance(x, (str, int))]
        except Exception:
            pass
        return []

    def set_recent_nodes(self, node_ids: List[str]) -> None:
        """持久化存储最近使用过的节点 ID 列表"""
        import json
        clean_ids = [str(x) for x in node_ids if isinstance(x, (str, int))][:20]
        self.set_setting("recent_nodes_json", json.dumps(clean_ids))

    @staticmethod
    def _row_to_m(r: sqlite3.Row) -> MeasurementRecord:
        return MeasurementRecord(
            r["measurement_id"], r["endpoint_id"], r["node_id"], r["measured_at"],
            bool(r["is_reachable"]), r["dns_latency_ms"], r["tcp_latency_ms"],
            r["direct_https_latency_ms"], r["packet_loss_pct"], r["jitter_ms"],
            r["error_message"], r["web_score"], r["video_score"],
            r["stability_score"], r["overall_score"]
        )
