import json
import os
import sqlite3
from collections import Counter
from pathlib import Path
from typing import Any


DEFAULT_DB_PATH = Path(os.getenv("CYBERSCAN_DB_PATH", "cyberscan.db"))
CACHE_TTL_HOURS = int(os.getenv("CYBERSCAN_CACHE_TTL_HOURS", "12"))


def _connect() -> sqlite3.Connection:
    db_path = Path(DEFAULT_DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scan_cache (
                resource_type TEXT NOT NULL,
                indicator TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (resource_type, indicator)
            );

            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                resource_type TEXT NOT NULL,
                indicator TEXT NOT NULL,
                status TEXT NOT NULL,
                risk TEXT,
                source TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS scan_submissions (
                analysis_id TEXT PRIMARY KEY,
                resource_type TEXT NOT NULL,
                indicator TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
            """
        )


def get_cached_result(resource_type: str, indicator: str) -> dict[str, Any] | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT response_json
            FROM scan_cache
            WHERE resource_type = ?
              AND indicator = ?
              AND datetime(created_at) >= datetime('now', ?)
            """,
            (resource_type, indicator, f"-{CACHE_TTL_HOURS} hours"),
        ).fetchone()

    if not row:
        return None
    return json.loads(row["response_json"])


def save_cached_result(resource_type: str, indicator: str, response: dict[str, Any]) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_cache (resource_type, indicator, response_json, created_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(resource_type, indicator)
            DO UPDATE SET
                response_json = excluded.response_json,
                created_at = CURRENT_TIMESTAMP
            """,
            (resource_type, indicator, json.dumps(response)),
        )


def record_history(
    resource_type: str,
    indicator: str,
    status: str,
    response: dict[str, Any],
    risk: str | None = None,
    source: str = "live",
) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_history (resource_type, indicator, status, risk, source, response_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (resource_type, indicator, status, risk, source, json.dumps(response)),
        )


def save_submission(analysis_id: str, resource_type: str, indicator: str) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scan_submissions (analysis_id, resource_type, indicator, created_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(analysis_id)
            DO UPDATE SET
                resource_type = excluded.resource_type,
                indicator = excluded.indicator,
                created_at = CURRENT_TIMESTAMP
            """,
            (analysis_id, resource_type, indicator),
        )


def get_submission(analysis_id: str) -> dict[str, str] | None:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT analysis_id, resource_type, indicator
            FROM scan_submissions
            WHERE analysis_id = ?
            """,
            (analysis_id,),
        ).fetchone()

    if not row:
        return None
    return dict(row)


def list_history(limit: int = 20) -> list[dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, resource_type, indicator, status, risk, source, created_at
            FROM scan_history
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    return [dict(row) for row in rows]


def get_summary() -> dict[str, Any]:
    history = list_history(limit=100)
    total_scans = len(history)
    by_risk = Counter(item["risk"] or "UNKNOWN" for item in history)
    by_type = Counter(item["resource_type"] for item in history)

    latest = history[:5]
    return {
        "total_scans": total_scans,
        "by_risk": dict(by_risk),
        "by_type": dict(by_type),
        "latest": latest,
        "cache_ttl_hours": CACHE_TTL_HOURS,
    }
