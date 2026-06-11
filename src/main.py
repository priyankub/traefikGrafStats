#!/usr/bin/env python3
"""traefikGrafStats - Processing Traefik JSON logs directly to InfluxDB."""

import glob
import logging
import os
import signal
import sys
import threading

from config import load_config, LOGS_DIR
from log_watcher import LogWatcher
from log_parser import parse_traefik_json_line
from geo_lookup import GeoLookup
from abuse_checker import AbuseChecker
from ua_parser_util import parse_user_agent
from influx_writer import InfluxWriter
from ip_classifier import IPClassifier

VERSION = "4.0.0-traefik"

_log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, _log_level, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("traefikGrafStats")

# Logs processed details at INFO level when true
VERBOSE = os.getenv("VERBOSE_LOGGING", "FALSE").upper() == "TRUE"

stop_event = threading.Event()


def main():
    logger.info("traefikGrafStats v%s starting (log_level=%s, verbose=%s)", VERSION, _log_level, VERBOSE)

    cfg = load_config()

    # Initialize shared persistence/cache resources
    geo = GeoLookup(cfg["has_city_db"], cfg["has_asn_db"])
    abuse = AbuseChecker(cfg["abuseip_key"])
    influx = InfluxWriter(cfg["influx_host"], cfg["influx_token"], cfg["influx_org"], cfg["influx_bucket"])
    classifier = IPClassifier(cfg["external_ip"], cfg["has_monitoring_file"])

    # Statistics reporting counters
    _stats = {"processed": 0, "errors": 0, "written": 0}
    _stats_lock = threading.Lock()

    def handle_access_line(line: str):
        entry = parse_traefik_json_line(line)
        if not entry:
            logger.debug("Failed to parse log line as JSON: %.200s", line)
            return

        ip_type = classifier.classify(entry.outside_ip)
        ua_info = parse_user_agent(entry.user_agent)

        # Classify redirect actions based on standard HTTP codes (301, 302, 307, 308)
        is_redirect = entry.status_code in (301, 302, 307, 308)

        if VERBOSE:
            logger.info("[ACCESS] %s %s -> %s (status=%d, len=%d, type=%s, redirect=%s)",
                        entry.outside_ip, entry.domain, entry.target_ip,
                        entry.status_code, entry.length, ip_type, is_redirect)

        try:
            if ip_type == "internal":
                logger.debug("Internal IP: %s -> %s", entry.outside_ip, entry.domain)
                if cfg["internal_logs"]:
                    influx.write_internal(
                        "InternalRProxyIPs", entry.outside_ip, entry.domain,
                        entry.length, entry.target_ip, entry.timestamp,
                        entry.status_code, ua_info,
                    )
            elif ip_type == "monitoring":
                logger.debug("Monitoring IP: %s -> %s", entry.outside_ip, entry.domain)
                if cfg["monitoring_logs"]:
                    geo_result = geo.lookup(entry.outside_ip)
                    abuse_scores = abuse.check(entry.outside_ip)
                    influx.write_external(
                        "MonitoringRProxyIPs", entry.outside_ip, entry.domain,
                        entry.length, entry.target_ip, entry.timestamp,
                        entry.status_code, ua_info, geo_result, abuse_scores,
                        abuse_enabled=abuse.enabled,
                    )
            else:
                geo_result = geo.lookup(entry.outside_ip)
                abuse_scores = abuse.check(entry.outside_ip)
                
                # Routes to "Redirections" or "ReverseProxyConnections" measurements
                measurement = "Redirections" if is_redirect else "ReverseProxyConnections"
                influx.write_external(
                    measurement, entry.outside_ip, entry.domain,
                    entry.length, entry.target_ip, entry.timestamp,
                    entry.status_code, ua_info, geo_result, abuse_scores,
                    abuse_enabled=abuse.enabled,
                )
            with _stats_lock:
                _stats["written"] += 1
        except Exception as e:
            logger.error("InfluxDB write FAILED for %s %s -> %s: %s", entry.outside_ip, entry.domain, entry.target_ip, e)
            with _stats_lock:
                _stats["errors"] += 1

        with _stats_lock:
            _stats["processed"] += 1

    # Search for standard Traefik access log names in LOGS_DIR
    threads: list[threading.Thread] = []
    access_logs = sorted(glob.glob(os.path.join(LOGS_DIR, "access*.log")))
    logger.info("Found %d access log files in %s", len(access_logs), LOGS_DIR)

    for logfile in access_logs:
        watcher = LogWatcher(logfile, handle_access_line, stop_event)
        t = threading.Thread(target=watcher.run, name=f"access:{os.path.basename(logfile)}", daemon=True)
        t.start()
        threads.append(t)

    if not threads:
        logger.warning("No access*.log files found to watch!")

    logger.info("Started %d log watcher threads", len(threads))

    def shutdown(signum, frame):
        logger.info("Received signal %d, stopping gracefully...", signum)
        stop_event.set()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Keep main thread alive until signal received
    try:
        stop_event.wait()
    except KeyboardInterrupt:
        stop_event.set()

    logger.info("Stats: processed=%d written=%d errors=%d", _stats["processed"], _stats["written"], _stats["errors"])
    logger.info("Closing services...")
    for t in threads:
        t.join(timeout=5)

    abuse.close()
    influx.close()
    geo.close()
    logger.info("traefikGrafStats shutdown complete")


if __name__ == "__main__":
    main()
