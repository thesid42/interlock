"""At-least-once exporter with durable retry batches and no policy authority."""

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from app.storage.clickhouse import ClickHouseAnalytics


class OutboxExporter:
    def __init__(self, database_path: str | Path, analytics: ClickHouseAnalytics):
        self.database_path = str(database_path)
        self.analytics = analytics
        self._lock = Lock()
        db = self._connect()
        try:
            db.execute("""CREATE TABLE IF NOT EXISTS export_batches (
                batch_id TEXT PRIMARY KEY, payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL, exported_at TEXT,
                attempts INTEGER NOT NULL DEFAULT 0, last_error TEXT
            )""")
            db.commit()
        finally:
            db.close()

    def _connect(self):
        db = sqlite3.connect(self.database_path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def backlog(self) -> dict:
        db = self._connect()
        try:
            row = db.execute("""SELECT count(*) AS pending,
                min(a.recorded_ts) AS oldest_recorded_ts
                FROM outbox o JOIN audit_events a USING(event_id)
                WHERE o.exported_at IS NULL""").fetchone()
            error = db.execute("""SELECT last_error FROM outbox
                WHERE exported_at IS NULL AND last_error IS NOT NULL
                ORDER BY rowid DESC LIMIT 1""").fetchone()
            return {**dict(row), "last_error": error["last_error"] if error else None}
        finally:
            db.close()

    def _batch(self, limit: int):
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            batch = db.execute("""SELECT * FROM export_batches WHERE exported_at IS NULL
                ORDER BY created_at, batch_id LIMIT 1""").fetchone()
            if batch:
                batch_id, payload = batch["batch_id"], batch["payload_json"]
            else:
                rows = db.execute("""SELECT a.payload_json FROM audit_events a
                    JOIN outbox o USING(event_id) WHERE o.exported_at IS NULL
                    ORDER BY a.event_seq LIMIT ?""", (limit,)).fetchall()
                if not rows:
                    db.commit()
                    return None
                payload = json.dumps([json.loads(row["payload_json"]) for row in rows], sort_keys=True, separators=(",", ":"))
                batch_id = hashlib.sha256(payload.encode()).hexdigest()
                db.execute("INSERT INTO export_batches(batch_id,payload_json,created_at) VALUES(?,?,?)",
                    (batch_id, payload, datetime.now(timezone.utc).isoformat()))
            events = json.loads(payload)
            db.execute("UPDATE export_batches SET attempts=attempts+1 WHERE batch_id=?", (batch_id,))
            db.executemany("UPDATE outbox SET attempts=attempts+1 WHERE event_id=?",
                [(event["event_id"],) for event in events])
            db.commit()
            return batch_id, events
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def flush(self, limit: int = 100) -> dict:
        limit = max(1, min(int(limit), 1000))
        if not self.analytics.configured:
            return {"state": "unavailable", "exported": 0, **self.backlog()}
        with self._lock:
            batch = self._batch(limit)
            if batch is None:
                return {"state": "idle", "exported": 0, **self.backlog()}
            batch_id, events = batch
            error = None
            try:
                self.analytics.insert_events(events, batch_id)
            except Exception as exc:
                error = f"Export failed: {type(exc).__name__}"
            db = self._connect()
            try:
                db.execute("BEGIN IMMEDIATE")
                if error:
                    db.execute("UPDATE export_batches SET last_error=? WHERE batch_id=?", (error, batch_id))
                    db.executemany("UPDATE outbox SET last_error=? WHERE event_id=?",
                        [(error, event["event_id"]) for event in events])
                else:
                    exported_at = datetime.now(timezone.utc).isoformat()
                    db.execute("UPDATE export_batches SET exported_at=?,last_error=NULL WHERE batch_id=?", (exported_at, batch_id))
                    db.executemany("UPDATE outbox SET exported_at=?,last_error=NULL WHERE event_id=?",
                        [(exported_at, event["event_id"]) for event in events])
                db.commit()
            except BaseException:
                db.rollback()
                raise
            finally:
                db.close()
            return {"state": "failed" if error else "exported", "batch_id": batch_id,
                    "exported": 0 if error else len(events), **self.backlog()}
