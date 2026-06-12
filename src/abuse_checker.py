"""AbuseIPDB checker with SQLite WAL-mode cache (thread-safe, Jitter, Dynamic TTL, Stale-While-Revalidate)."""

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
        """Clean up expired entries. Since dynamic scaling supports up to 14 days,
        we change the global purge cutoff to 14 days (336h) to prevent deleting active long-lived caches."""
        max_ttl_hours = 336
        cutoff = time.time() - max_ttl_hours * 3600
        if self._conn:
            self._conn.execute("DELETE FROM abuse_cache WHERE fetched_at < ?", (cutoff,))
            self._conn.commit()
            logger.info("Cleaned up expired abuse cache entries (older than %dh)", max_ttl_hours)

    @property
    def enabled(self) -> bool:
        return self._api_key is not None

    def check(self, ip: str) -> tuple[int, int]:
        """Returns (confidence_score, total_reports). (0, 0) if unavailable.
        Employs dynamic TTL thresholds, cache jitter, and stale-while-revalidate background fetches."""
        if not self._api_key or not self._conn:
            return 0, 0

        with self._lock:
            row = self._conn.execute(
                "SELECT confidence_score, total_reports, fetched_at FROM abuse_cache WHERE ip = ?",
                (ip,),
            ).fetchone()

        if row:
            confidence_score, total_reports, fetched_at = row

            # --- OPTIMIZATION 1: DYNAMIC TTL SCALING ---
            # Highly malicious IPs stay malicious. Cache them longer to conserve our API key budget.
            if confidence_score >= 90:
                ttl_hours = 336  # Keep critical offenders cached for 14 days
            elif confidence_score >= 50:
                ttl_hours = 168  # Keep suspicious IPs cached for 7 days
            else:
                ttl_hours = CACHE_TTL_HOURS  # Default (48 hours) for clean or low-score IPs

            is_expired = (time.time() - fetched_at) >= (ttl_hours * 3600)

            if is_expired:
                # --- OPTIMIZATION 2: STALE-WHILE-REVALIDATE ---
                # Entry is stale. Instantly return historical data to the dashboard,
                # then spawn a background thread to quietly refresh the API cache.
                logger.debug("AbuseIPDB cache entry for %s is stale (expired after %dh). Triggering lazy revalidation.", ip, ttl_hours)
                threading.Thread(target=self._refresh_api_async, args=(ip,), daemon=True).start()
            else:
                logger.debug("AbuseIPDB cache HIT for %s (TTL: %dh, valid for %d more hours)",
                             ip, ttl_hours, int((ttl_hours * 3600 - (time.time() - fetched_at)) / 3600))

            return confidence_score, total_reports

        # Cold Cache Miss: We have no stale data to fall back on. 
        # Perform a standard synchronous lookup to establish the baseline entry.
        logger.debug("AbuseIPDB cache cold MISS for %s", ip)
        try:
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Accept": "application/json", "Key": self._api_key},
                timeout=10,
            )
            resp.raise_for_status()
            api_data = resp.json().get("data", {})
            cs = api_data.get("abuseConfidenceScore", 0)
            tr = api_data.get("totalReports", 0)

            # --- OPTIMIZATION 3: CACHE JITTER ---
            # Shift the timestamp by a random interval (+/- 6 hours) to prevent clustered expiry storms.
            jitter_seconds = random.randint(-6 * 3600, 6 * 3600)
            fetched_at = time.time() + jitter_seconds

            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO abuse_cache (ip, confidence_score, total_reports, data_json, fetched_at) VALUES (?, ?, ?, ?, ?)",
                    (ip, cs, tr, json.dumps(api_data), fetched_at),
                )
                self._conn.commit()
            return cs, tr
        except Exception as e:
            logger.warning("AbuseIPDB API error for %s: %s", ip, e)
            return 0, 0

    def _refresh_api_async(self, ip: str):
        """Worker executing asynchronous API checks in the background to prevent lock-blocking."""
        with self._lock:
            if ip in self._pending_refreshes:
                return  # Prevent duplicating ongoing revalidations for the same IP
            self._pending_refreshes.add(ip)

        try:
            logger.debug("Asynchronously revalidating IP %s in background thread...", ip)
            resp = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Accept": "application/json", "Key": self._api_key},
                timeout=10,
            )
            resp.raise_for_status()
            api_data = resp.json().get("data", {})
            cs = api_data.get("abuseConfidenceScore", 0)
            tr = api_data.get("totalReports", 0)

            # Apply cache jitter to background refreshes too
            jitter_seconds = random.randint(-6 * 3600, 6 * 3600)
            fetched_at = time.time() + jitter_seconds

            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO abuse_cache (ip, confidence_score, total_reports, data_json, fetched_at) VALUES (?, ?, ?, ?, ?)",
                    (ip, cs, tr, json.dumps(api_data), fetched_at),
                )
                self._conn.commit()
            logger.debug("Asynchronous revalidation complete for %s (Score: %d%%)", ip, cs)
        except Exception as e:
            logger.warning("Async background AbuseIPDB API update failed for %s: %s", ip, e)
        finally:
            with self._lock:
                self._pending_refreshes.discard(ip)

    def close(self):
        if self._conn:
            self._conn.close()
