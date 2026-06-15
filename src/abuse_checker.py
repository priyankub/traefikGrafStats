"""AbuseIPDB checker with SQLite WAL-mode cache (Circuit Breaker, Jitter, Dynamic TTL, SWR)."""

import json
import logging
import os
import random
import sqlite3
import threading
import time

import requests

from config import ABUSEIP_CACHE_DB, ABUSEIP_CACHE_JSON, CACHE_TTL_HOURS, DATA_DIR

logger = logging.getLogger(__name__)

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS abuse_cache (
    ip TEXT PRIMARY KEY,
    confidence_score INTEGER,
    total_reports INTEGER,
    data_json TEXT,
    fetched_at REAL
)
"""


class AbuseChecker:
    def __init__(self, api_key: str | None):
        self._api_key = api_key
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self._pending_refreshes = set()  # Tracks active background API requests to prevent duplicates
        self._rate_limit_reset_time = 0.0     
        if not api_key:
            logger.info("AbuseIPDB disabled (no API key)")
            return
        self._init_db()

    def _init_db(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        self._conn = sqlite3.connect(ABUSEIP_CACHE_DB, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(_CREATE_TABLE)
        self._conn.commit()
        self._migrate_json_cache()
        self._cleanup_expired()

    def _migrate_json_cache(self):
        """Migrate existing JSON cache to SQLite on first run."""
        if not os.path.isfile(ABUSEIP_CACHE_JSON):
            return
        try:
            with open(ABUSEIP_CACHE_JSON, "r") as f:
                data = json.load(f)
            count = 0
            for ip, entry in data.items():
                ts = entry.get("timestamp", 0)
                d = entry.get("data", {})
                self._conn.execute(
                    "INSERT OR IGNORE INTO abuse_cache (ip, confidence_score, total_reports, data_json, fetched_at) VALUES (?, ?, ?, ?, ?)",
                    (ip, d.get("abuseConfidenceScore", 0), d.get("totalReports", 0), json.dumps(d), ts),
                )
                count += 1
            self._conn.commit()
            # Rename old file
            os.rename(ABUSEIP_CACHE_JSON, ABUSEIP_CACHE_JSON + ".migrated")
            logger.info("Migrated %d entries from JSON cache to SQLite", count)
        except Exception as e:
            logger.warning("JSON cache migration failed: %s", e)

    def _cleanup_expired(self):
        """Clean up expired entries older than 14 days."""
        max_ttl_hours = 336
        cutoff = time.time() - max_ttl_hours * 3600
        if self._conn:
            self._conn.execute("DELETE FROM abuse_cache WHERE fetched_at < ?", (cutoff,))
            self._conn.commit()
            logger.info("Cleaned up expired abuse cache entries (older than %dh)", max_ttl_hours)

    @property
    def enabled(self) -> bool:
        return self._api_key is not None

    def _execute_api_request(self, ip: str) -> dict | None:
        """Centralized network gatekeeper that handles HTTP requests and locks the circuit breaker."""
        if time.time() < self._rate_limit_reset_time:
            logger.debug("AbuseIPDB circuit breaker active. Skipping network request for %s", ip)
            return None

        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Accept": "application/json", "Key": self._api_key},
                timeout=10,
            )
            resp.raise_for_status()
            return resp.json().get("data", {})

        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 429:
                retry_after = e.response.headers.get("Retry-After")
                if retry_after and retry_after.isdigit():
                    pause_seconds = int(retry_after)
                else:
                    # Fallback: Pause requests for 60 minutes before testing the API again
                    pause_seconds = 3600
                
                self._rate_limit_reset_time = time.time() + pause_seconds
                logger.warning("AbuseIPDB API quota exceeded (429). Circuit breaker engaged for %d seconds.", pause_seconds)
            else:
                logger.warning("AbuseIPDB API HTTP error for %s: %s", ip, e)
            return None
        except Exception as e:
            logger.warning("AbuseIPDB connection error for %s: %s", ip, e)
            return None

    def check(self, ip: str) -> tuple[int, int]:
        """Returns (confidence_score, total_reports). (0, 0) if unavailable."""
        if not self._api_key or not self._conn:
            return 0, 0

        with self._lock:
            row = self._conn.execute(
                "SELECT confidence_score, total_reports, fetched_at FROM abuse_cache WHERE ip = ?",
                (ip,),
            ).fetchone()

        if row:
            confidence_score, total_reports, fetched_at = row

            # Dynamic TTL calculations
            if confidence_score >= 90:
                ttl_hours = 336  
            elif confidence_score >= 50:
                ttl_hours = 168  
            else:
                ttl_hours = CACHE_TTL_HOURS  

            if (time.time() - fetched_at) >= (ttl_hours * 3600):
                logger.debug("AbuseIPDB cache entry for %s is stale. Triggering lazy revalidation.", ip)
                threading.Thread(target=self._refresh_api_async, args=(ip,), daemon=True).start()
            else:
                logger.debug("AbuseIPDB cache HIT for %s", ip)

            return confidence_score, total_reports

        # Cold Cache Miss: Execute request via safe centralized gatekeeper
        api_data = self._execute_api_request(ip)
        if not api_data:
            return 0, 0

        cs = api_data.get("abuseConfidenceScore", 0)
        tr = api_data.get("totalReports", 0)

        jitter_seconds = random.randint(-6 * 3600, 6 * 3600)
        fetched_at = time.time() + jitter_seconds

        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO abuse_cache (ip, confidence_score, total_reports, data_json, fetched_at) VALUES (?, ?, ?, ?, ?)",
                (ip, cs, tr, json.dumps(api_data), fetched_at),
            )
            self._conn.commit()
        return cs, tr

    def _refresh_api_async(self, ip: str):
        """Worker executing asynchronous API checks safely via centralized gatekeeper."""
        with self._lock:
            if ip in self._pending_refreshes:
                return  
            self._pending_refreshes.add(ip)

        try:
            logger.debug("Asynchronously revalidating IP %s in background thread...", ip)
            api_data = self._execute_api_request(ip)
            
            if api_data:
                cs = api_data.get("abuseConfidenceScore", 0)
                tr = api_data.get("totalReports", 0)

                jitter_seconds = random.randint(-6 * 3600, 6 * 3600)
                fetched_at = time.time() + jitter_seconds

                with self._lock:
                    self._conn.execute(
                        "INSERT OR REPLACE INTO abuse_cache (ip, confidence_score, total_reports, data_json, fetched_at) VALUES (?, ?, ?, ?, ?)",
                        (ip, cs, tr, json.dumps(api_data), fetched_at),
                    )
                    self._conn.commit()
                logger.debug("Asynchronous revalidation complete for %s (Score: %d%%)", ip, cs)
        finally:
            with self._lock:
                self._pending_refreshes.discard(ip)

    def close(self):
        if self._conn:
            self._conn.close()