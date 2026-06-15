# traefikGrafStats 📈

`traefikGrafStats` is a platform-agnostic, high-performance log-tailing service designed specifically for **Traefik access logs in JSON format**.

The application monitors your Traefik logs in real-time, extracts geo-coordinates via MaxMind GeoLite2, checks IP safety ratings through AbuseIPDB with an advanced resilient circuit-breaker cache, and pushes structured time-series metrics directly into **InfluxDB v2** for display on beautiful Grafana map dashboards.

This project is a complete architectural rewrite and drop-in modernization of the excellent [smilebasti/npmGrafStats](https://github.com/smilebasti/npmGrafStats) project, replacing Nginx regex parsing with native, high-speed JSON stream decoding.

## 🚀 Key Features

* **High-Speed JSON Parser:** Native, structured deserialization of Traefik logs. Zero regex performance hits or parsing breakage due to upstream log format shifts.

* **Resilient Threat Cache (Quota Guard):** Built specifically for the AbuseIPDB Free Tier (1,000 requests/day):

  * **Circuit Breaker:** Instantly stops making outbound HTTP requests when a `429 Too Many Requests` status is hit, resuming automatically only after the limit resets.

  * **Stale-While-Revalidate (SWR):** Instantly returns cached IP data to InfluxDB to prevent log processing lag, updating stale records silently on background threads.

  * **Dynamic TTL Scaling:** Suspicious and highly malicious IPs (Confidence Score $\ge$ 50%) are automatically cached for 7 to 14 days to conserve API requests.

  * **Jitter:** Introduces a random variance to entry timestamps to prevent massive waves of simultaneous database expirations.

* **Platform-Agnostic Build:** Full multi-architecture support (`linux/amd64`, `linux/arm64`) optimized out-of-the-box for Raspberry Pi 5.

* **Internal / External Routing:** Intelligently separates metrics for external web requests, internal infrastructure traffic, and monitoring probes.

## ⚙️ Configuration Reference (Environment Variables)

The application is configured primarily through environment variables passed to the Docker container (manually or via a .env file).

### **Application Environment Variables**

| Variable Name | Default Value | Description |
| :---- | :---- | :---- |
| INFLUX\_HOST | http://localhost:8086 | Full URL to your InfluxDB v2 instance. |
| INFLUX\_TOKEN | *None (Required)* | InfluxDB API All-Access token. Can also be loaded from /data/influxdb-token.txt. |
| INFLUX\_ORG | npmgrafstats | The organization name set up in your InfluxDB instance. |
| INFLUX\_BUCKET | npmgrafstats | Target bucket name. Retained to match historical npmGrafStats dashboard layouts. |
| ABUSEIP\_KEY | *None* | Optional. Your AbuseIPDB API key. Can also be loaded from /data/abuseipdb-key.txt. |
| INTERNAL\_LOGS | false | Set to true to log local network requests (internal IPs) to InfluxDB. |
| MONITORING\_LOGS | false | Set to true to log monitoring and health-check IPs to InfluxDB. |
| EXTERNAL\_IP | *None* | Optional. Explicitly sets your own external WAN IP to distinguish loopback proxy traffic. Can also be read from /data/external-ip.txt. |
| LOG\_LEVEL | INFO | Standard application logging verbosity (DEBUG, INFO, WARNING, ERROR). |
| VERBOSE\_LOGGING | FALSE | Set to TRUE to output every parsed log entry details directly to standard output. |

### **Docker Volume Mounts**

| Container Directory | Host Target Mount | Purpose |
| :---- | :---- | :---- |
| /logs | /home/pranks/docker/traefik/log | Mounted path containing your Traefik JSON access\*.log files to tail. |
| /geolite | ./geolite | Shared with geoipupdate containing GeoLite2-City.mmdb and GeoLite2-ASN.mmdb. |
| /data | ./npmgraf\_data | Persistent storage for SQLite cache (abuseip\_cache.db) and manual text configuration keys. |

## 🛠️ Infrastructure Setup

### 1. Configure Traefik Access Logs (JSON)

For this service to parse logs, Traefik must write access logs in the **JSON** format. In your Traefik static configuration file (`traefik.yml` or CLI labels), ensure the following is configured:

```
# CLI Flags:
- "--accesslog=true"
- "--accesslog.filepath=/logs/access.log"
- "--accesslog.format=json"

```

### 2. Set Directory Permissions (Critical)

Because the container drops root privileges to run as a secure non-root `appuser` (UID 1000), you must ensure your local data directory is writable by this user ID:

```
sudo chown -R 1000:1000 /home/pranks/docker/npmplus/npmgraf

```

## 🐳 Integration Deployment (`docker-compose.yml`)

The complete production-ready stack integrates InfluxDB, Grafana, `geoipupdate` (automated MaxMind sync), and `traefikGrafStats`.

This stack exposes no database ports directly to the host machine. Instead, Traefik dynamically routes your domain over a secure `reverse_proxy` network:

```
services:
  influxdb:
    cpu_shares: 90
    container_name: influxdb
    deploy:
      resources:
        limits:
          memory: 4049M
    environment:
      - DOCKER_INFLUXDB_INIT_BUCKET=npmgrafstats
      - DOCKER_INFLUXDB_INIT_MODE=setup
      - DOCKER_INFLUXDB_INIT_ORG=npmgrafstats
      - DOCKER_INFLUXDB_INIT_PASSWORD=your_secure_influx_password
      - DOCKER_INFLUXDB_INIT_USERNAME=admin
    hostname: influxdb
    image: influxdb:2.7-alpine
    restart: unless-stopped
    volumes:
      - /home/pranks/docker/npmplus/influxdbv2/data:/var/lib/influxdb2
      - /home/pranks/docker/npmplus/influxdbv2/etc:/etc/influxdb2
    networks:
      - reverse_proxy
    privileged: false
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.rpiinflux.rule=Host(`rpiinflux.FQDN`)"
      - "traefik.http.routers.rpiinflux.middlewares=https-redirect@file, default-headers@file"      
      - "traefik.http.routers.rpiinflux.entrypoints=https"
      - "traefik.http.routers.rpiinflux.tls=true"
      - "traefik.http.services.rpiinflux.loadbalancer.server.port=8086"
      - "traefik.http.services.rpiinflux.loadbalancer.server.scheme=http"

  traefikgraf:
    container_name: traefikgraf
    image: ghcr.io/priyankub/traefikgrafstats:latest
    restart: unless-stopped
    environment:
      - ABUSEIP_KEY=${ABUSEIP_KEY}
      - INFLUX_HOST=http://influxdb:8086
      - INFLUX_ORG=npmgrafstats
      - INFLUX_BUCKET=npmgrafstats
      - INFLUX_TOKEN=${INFLUX_TOKEN}
      - INTERNAL_LOGS=true
      - MONITORING_LOGS=true
      - LOG_LEVEL=INFO
      - VERBOSE_LOGGING=FALSE
    hostname: traefikgraf
    volumes:
      - type: bind
        source: /home/pranks/docker/traefik/log
        target: /logs
      - type: bind
        source: /home/pranks/docker/npmplus/npmplus/goaccess/geoip
        target: /geolite
      - type: bind
        source: /home/pranks/docker/npmplus/npmgraf
        target: /data
    networks:
      - reverse_proxy
    privileged: false
    depends_on:
      - influxdb

  geoipupdate:
    cpu_shares: 90
    container_name: geoipupdate
    deploy:
      resources:
        limits:
          memory: 4049M
        environment:
          - GEOIPUPDATE_ACCOUNT_ID=${GEOIPUPDATE_ACCOUNT_ID}
          - GEOIPUPDATE_EDITION_IDS=GeoLite2-Country GeoLite2-City GeoLite2-ASN
          - GEOIPUPDATE_FREQUENCY=24
          - GEOIPUPDATE_LICENSE_KEY=${GEOIPUPDATE_LICENSE_KEY}
          - TZ=America/Chicago
        hostname: geoipupdate
        image: ghcr.io/maxmind/geoipupdate:latest
        restart: always
        volumes:
          - type: bind
            source: /home/pranks/docker/npmplus/npmplus/goaccess/geoip
            target: /usr/share/GeoIP
        networks:
          - reverse_proxy
        privileged: false

networks:
  reverse_proxy:
    external: true

```

### Local environment Configuration (`.env`)

Place your keys and credentials in a local `.env` file right next to your `docker-compose.yml`. This file is ignored by Git automatically:

```
# InfluxDB Auth
INFLUX_TOKEN=INFLUX_TOKEN_KEY

# Maxmind GeoIP Configuration
GEOIPUPDATE_ACCOUNT_ID=MAXMIND_ID
GEOIPUPDATE_LICENSE_KEY=MAXMIND_KEY

# Threat Identification
ABUSEIP_KEY=ABUSEIP_KEY

```

## 📊 Dashboard Import

Because this application preserves the precise measurement structures, tag names, and coordinates mapped by the original project, existing dashboards are immediately compatible.

To add the map to Grafana:

1. Ensure Grafana is connected to your InfluxDB datasource via **Flux query language** using your organization and bucket settings.

2. Import your dashboard JSON files using InfluxDBv2 panels targeting `ReverseProxyConnections` and `Redirections` measurements.

## ⚖️ License & Attribution

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License v3** as published by the Free Software Foundation.

### Attribution

* Base project and inspiration: [smilebasti/npmGrafStats](https://github.com/smilebasti/npmGrafStats).
