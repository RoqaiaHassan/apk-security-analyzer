import sqlite3
import os
import json
from typing import Dict, Any, List, Optional

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "analyzer.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        app_name TEXT,
        package_name TEXT,
        version_name TEXT,
        file_name TEXT,
        file_size INTEGER,
        sha256 TEXT,
        md5 TEXT,
        sha1 TEXT,
        security_score INTEGER,
        critical_count INTEGER,
        high_count INTEGER,
        medium_count INTEGER,
        low_count INTEGER,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        raw_results JSON
    );
    """)
    conn.commit()
    conn.close()

def save_scan(scan_data: Dict[str, Any]):
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (
            id, app_name, package_name, version_name, file_name, file_size,
            sha256, md5, sha1, security_score, critical_count, high_count,
            medium_count, low_count, raw_results
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_data["id"],
        scan_data.get("app_name", "Unknown"),
        scan_data.get("package_name", "com.example.app"),
        scan_data.get("version_name", "1.0"),
        scan_data.get("file_name", ""),
        scan_data.get("file_size", 0),
        scan_data.get("sha256", ""),
        scan_data.get("md5", ""),
        scan_data.get("sha1", ""),
        scan_data.get("security_score", 100),
        scan_data.get("counts", {}).get("Critical", 0),
        scan_data.get("counts", {}).get("High", 0),
        scan_data.get("counts", {}).get("Medium", 0),
        scan_data.get("counts", {}).get("Low", 0),
        json.dumps(scan_data)
    ))
    conn.commit()
    conn.close()

def get_all_scans() -> List[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, app_name, file_name, created_at, security_score, critical_count, high_count, medium_count, low_count FROM scans ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT raw_results FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row and row["raw_results"]:
        return json.loads(row["raw_results"])
    return None

def delete_scan(scan_id: str) -> bool:
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    affected = cursor.rowcount
    conn.close()
    return affected > 0
