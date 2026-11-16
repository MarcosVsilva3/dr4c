"""SQLite storage for scan history and Core Recon observations."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from datetime import datetime, timezone

from dr4c.core.models import ScanResult


class Database:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA foreign_keys = ON")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY, target TEXT NOT NULL,
                    started_at TEXT NOT NULL, result_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(scan_id),
                    asset_type TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL,
                    scope_status TEXT NOT NULL, data_json TEXT NOT NULL,
                    UNIQUE(scan_id, asset_type, value)
                );
                CREATE TABLE IF NOT EXISTS http_services (
                    id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(scan_id),
                    target TEXT NOT NULL, status_code INTEGER, data_json TEXT NOT NULL,
                    UNIQUE(scan_id, target)
                );
                CREATE TABLE IF NOT EXISTS dns_records (
                    id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(scan_id),
                    hostname TEXT NOT NULL, record_type TEXT NOT NULL, value TEXT NOT NULL,
                    source TEXT NOT NULL, ttl INTEGER,
                    UNIQUE(scan_id, hostname, record_type, value)
                );
                CREATE TABLE IF NOT EXISTS open_ports (
                    id INTEGER PRIMARY KEY, scan_id TEXT NOT NULL REFERENCES scans(scan_id),
                    hostname TEXT NOT NULL, address TEXT NOT NULL, port INTEGER NOT NULL,
                    state TEXT NOT NULL, UNIQUE(scan_id, hostname, address, port)
                );
            """)
            for version in (1, 2):
                db.execute(
                    "INSERT OR IGNORE INTO schema_migrations(version,applied_at) VALUES(?,?)",
                    (version, datetime.now(timezone.utc).isoformat()),
                )

    def save_scan(self, result: ScanResult) -> None:
        self.initialize()
        with sqlite3.connect(self.path) as db:
            db.execute("PRAGMA foreign_keys = ON")
            db.execute(
                "INSERT INTO scans(scan_id,target,started_at,result_json) VALUES(?,?,?,?)",
                (result.scan_id, result.target, result.started_at,
                 json.dumps(result.to_dict(), ensure_ascii=False)),
            )
            db.executemany(
                "INSERT INTO assets VALUES(?,?,?,?,?,?,?)",
                [(a.asset_id, result.scan_id, a.asset_type, a.value, a.source,
                  a.scope_status, json.dumps(a.to_dict(), ensure_ascii=False)) for a in result.assets],
            )
            db.executemany(
                "INSERT INTO http_services(scan_id,target,status_code,data_json) VALUES(?,?,?,?)",
                [(result.scan_id, s.target, s.status_code, json.dumps(s.to_dict(), ensure_ascii=False))
                 for s in result.http_services],
            )
            db.executemany(
                "INSERT INTO dns_records(scan_id,hostname,record_type,value,source,ttl) VALUES(?,?,?,?,?,?)",
                [(result.scan_id, record.hostname, record.record_type, record.value,
                  record.source, record.ttl) for record in result.dns_records],
            )
            db.executemany(
                "INSERT INTO open_ports(scan_id,hostname,address,port,state) VALUES(?,?,?,?,?)",
                [(result.scan_id, item.hostname, item.address, item.port, item.state)
                 for item in result.open_ports],
            )

    def get_scan(self, scan_id: str) -> dict | None:
        with sqlite3.connect(self.path) as db:
            row = db.execute("SELECT result_json FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return json.loads(row[0]) if row else None
