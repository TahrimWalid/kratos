"""
Anomaly Storage - Time-Series Database
======================================
Persists anomalies in SQLite for historical analysis and trending.
Enables: "Show me all HIGH severity anomalies from the last 7 days"
"""

from __future__ import annotations

import sqlite3
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Any, Optional


class AnomalyStore:
    """SQLite-based storage for network anomalies and findings."""
    
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
    
    def _init_schema(self):
        """Create tables if they don't exist."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS anomalies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    device_type TEXT,
                    severity TEXT NOT NULL,
                    score INTEGER,
                    reason TEXT,
                    recommendation TEXT,
                    UNIQUE(timestamp, src_ip, dst_ip, dst_port, protocol)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    finding_id TEXT UNIQUE NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT,
                    description TEXT,
                    evidence TEXT,
                    recommendation TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS daily_summary (
                    date TEXT PRIMARY KEY,
                    high_anomalies INTEGER DEFAULT 0,
                    medium_anomalies INTEGER DEFAULT 0,
                    low_anomalies INTEGER DEFAULT 0,
                    unique_devices INTEGER DEFAULT 0,
                    risk_trend TEXT DEFAULT 'stable'
                )
            """)
            
            conn.commit()
    
    def store_anomalies(self, anomalies: list[dict[str, Any]]) -> int:
        """Store list of anomalies. Returns count stored."""
        count = 0
        with sqlite3.connect(self.db_path) as conn:
            for anom in anomalies:
                try:
                    conn.execute("""
                        INSERT OR IGNORE INTO anomalies
                        (timestamp, src_ip, dst_ip, dst_port, protocol, device_type, severity, score, reason, recommendation)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        datetime.now().isoformat(),
                        anom.get("src_ip"),
                        anom.get("dst_ip"),
                        anom.get("dst_port"),
                        anom.get("protocol"),
                        anom.get("device_type"),
                        anom.get("severity"),
                        anom.get("anomaly_score"),
                        json.dumps(anom.get("reasons", [])),
                        anom.get("recommendation"),
                    ))
                    count += 1
                except sqlite3.IntegrityError:
                    pass  # Duplicate, skip
            conn.commit()
        return count
    
    def get_anomalies_by_severity(
        self, severity: str, days: int = 7
    ) -> list[dict[str, Any]]:
        """Get anomalies of specific severity from last N days."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM anomalies
                WHERE severity = ? AND timestamp > ?
                ORDER BY timestamp DESC
            """, (severity, cutoff)).fetchall()
            return [dict(row) for row in rows]
    
    def get_high_anomalies_last_days(self, days: int = 7) -> list[dict[str, Any]]:
        """Convenience: get all HIGH severity anomalies from last N days."""
        return self.get_anomalies_by_severity("HIGH", days)
    
    def get_trend(self, device_ip: str, days: int = 7) -> dict[str, Any]:
        """Get anomaly trend for a specific device."""
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute("""
                SELECT
                    DATE(timestamp) as date,
                    COUNT(*) as count,
                    COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high_count
                FROM anomalies
                WHERE src_ip = ? AND timestamp > ?
                GROUP BY DATE(timestamp)
                ORDER BY date
            """, (device_ip, cutoff)).fetchall()
        
        return {
            "device": device_ip,
            "daily_breakdown": [dict(row) for row in rows],
            "is_increasing": len(rows) > 1 and rows[-1][1] > rows[0][1],
        }
    
    def update_daily_summary(self) -> None:
        """Recalculate daily summaries."""
        today = datetime.now().date().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            stats = conn.execute("""
                SELECT
                    COUNT(CASE WHEN severity = 'HIGH' THEN 1 END) as high_count,
                    COUNT(CASE WHEN severity = 'MEDIUM' THEN 1 END) as med_count,
                    COUNT(CASE WHEN severity = 'LOW' THEN 1 END) as low_count,
                    COUNT(DISTINCT src_ip) as unique_devices
                FROM anomalies
                WHERE DATE(timestamp) = ?
            """, (today,)).fetchone()
            
            if stats:
                h, m, l, u = stats
                conn.execute("""
                    INSERT OR REPLACE INTO daily_summary
                    (date, high_anomalies, medium_anomalies, low_anomalies, unique_devices)
                    VALUES (?, ?, ?, ?, ?)
                """, (today, h or 0, m or 0, l or 0, u or 0))
                conn.commit()
    
    def get_weekly_summary(self, weeks: int = 1) -> list[dict[str, Any]]:
        """Get daily summaries for last N weeks."""
        cutoff = (datetime.now() - timedelta(weeks=weeks)).date().isoformat()
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM daily_summary
                WHERE date > ?
                ORDER BY date DESC
            """, (cutoff,)).fetchall()
            return [dict(row) for row in rows]
    
    def store_finding(self, finding: dict[str, Any]) -> bool:
        """Store a single finding."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO findings
                    (timestamp, finding_id, title, severity, category, description, evidence, recommendation)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    datetime.now().isoformat(),
                    finding.get("id"),
                    finding.get("title"),
                    finding.get("severity"),
                    finding.get("category") or finding.get("type"),
                    finding.get("description") or finding.get("title"),
                    json.dumps(finding.get("evidence", [])),
                    finding.get("recommendation") or "",
                ))
                conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
    
    def get_findings_by_category(self, category: str) -> list[dict[str, Any]]:
        """Get all findings in a category."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT * FROM findings
                WHERE category = ?
                ORDER BY timestamp DESC
            """, (category,)).fetchall()
            return [dict(row) for row in rows]
