# **traefikGrafStats 📈**

`traefikGrafStats` is a platform-agnostic, high-performance log-tailing service designed specifically for **Traefik access logs in JSON format**.

The application monitors your Traefik logs in real-time, extracts geo-coordinates via MaxMind GeoLite2, checks IP safety ratings through AbuseIPDB with an advanced resilient circuit-breaker cache, and pushes structured time-series metrics directly into **InfluxDB v2** for display on beautiful Grafana map dashboards.

This project is a complete architectural rewrite and drop-in modernization of the excellent [smilebasti/npmGrafStats](https://github.com/smilebasti/npmGrafStats) project, replacing Nginx regex parsing with native, high-speed JSON stream decoding.

## **🚀 Key Features**

* **High-Speed JSON Parser:** Native, structured deserialization of Traefik logs. Zero regex performance hits or parsing breakage due to upstream log format shifts.  
* **Secure Right-to-Left (RTL) Proxy Traversal:** Walk backwards through proxy chains (such as [ClientIP, EdgeProxy, InternalProxy]) and filter out local networks or loopbacks. Isolates the authentic public origin IP and prevents internal network logs from hitting downstream APIs.  
* **Resilient Threat Cache (Quota Guard):** Built specifically for the AbuseIPDB Free Tier (1,000 requests/day):  
  * **Circuit Breaker:** Instantly suspends outbound network queries when a 429 Too Many Requests is encountered, resuming automatically only after the limit resets.  
  * **Stale-While-Revalidate (SWR):** Instantly returns cached IP data to InfluxDB to avoid log stream bottlenecks, fetching fresh updates quietly on background threads.  
  * **Dynamic TTL Scaling:** Suspicious and highly malicious IPs (Confidence Score $\ge$ 50%) are automatically cached for 7 to 14 days to conserve API requests.
  * **Cache Jitter:** Adds random timestamp offsets to committed DB records to prevent coordinated expiration waves.  
* **Platform-Agnostic Build:** Full multi-architecture support (linux/amd64, linux/arm64) optimized out-of-the-box for Raspberry Pi 5.  
* **Traffic Routing Segmentation:** Intelligently isolates metrics for external web requests, internal infrastructure traffic, and monitoring checks.

## **⚙️ Configuration Reference (Environment Variables)**

The application is configured through environment variables passed to the Docker container or via persistent text files mounted inside /data.

### **Application Environment Variables**

| Variable Name | Default Value | Allowed Values | Description |
| :---- | :---- | :---- | :---- |
| INFLUX_HOST | http://influxdb:8086 | URL String | Full HTTP URL to your InfluxDB v2 instance. |
| INFLUX_TOKEN | *None (Required)* | Token String | InfluxDB API All-Access token. Can also be loaded from /data/influxdb-token.txt. |
| INFLUX_ORG | npmgrafstats | Name String | The organization name set up in your InfluxDB instance. |
| INFLUX_BUCKET | npmgrafstats | Name String | Target bucket name. Retained to match historical npmGrafStats dashboard layouts. |
| ABUSEIP_KEY | *None* | API Key String | Optional. Your AbuseIPDB API key. Can also be loaded from /data/abuseipdb-key.txt. |
| REDIRECTION_LOGS | FALSE | TRUE, FALSE, ONLY | Configures logging of HTTP HTTP $3xx$ redirect actions. TRUE logs redirects to Redirections measurement and normal requests to ReverseProxyConnections. FALSE skips redirect entries. ONLY logs only redirection events. |
| INTERNAL_LOGS | FALSE | TRUE, FALSE | Set to TRUE to log local network requests (internal IPs) to InfluxDB. |
| MONITORING_LOGS | FALSE | TRUE, FALSE | Set to TRUE to log monitoring and health-check IPs to InfluxDB. |
| EXTERNAL_IP | *None* | IP String | Optional override to explicitly set your own WAN IP. If unconfigured, dynamically resolved using https://ifconfig.me/ip. Can also be read from /data/external-ip.txt. |
| LOG_LEVEL | INFO | DEBUG, INFO, WARNING, ERROR | Standard logging verbosity threshold. |
| VERBOSE_LOGGING | FALSE | TRUE, FALSE | Set to TRUE to output detailed execution details for every log line directly to stdout. |

### **Docker Volume Mounts**

| Container Directory | Host Target Mount | Purpose |
| :---- | :---- | :---- |
| /logs | /home/pranks/docker/traefik/log | Mounted directory containing your active Traefik JSON access*.log files to tail. |
| /geolite | /home/pranks/docker/npmplus/npmplus/goaccess/geoip | Shared with geoipupdate container; contains your GeoLite2 City and ASN databases. |
| /data | /home/pranks/docker/npmplus/npmgraf | Persistent directory for SQLite threat cache (abuseip_cache.db), configuration fallbacks, and monitoring lists. |

### **Diagnostic Fallback Files (Local Configuration Overrides)**

Instead of specifying sensitive credentials as environment variables, you can store plain text files inside /data to configure services securely:

* /data/influxdb-token.txt — Populates InfluxDB Token.  
* /data/abuseipdb-key.txt — Populates AbuseIPDB Key.  
* /data/external-ip.txt — Configures your external WAN IP.  
* /data/monitoringips.txt — Standard newline-delimited list of monitoring IPs or CIDRs (e.g., 1.1.1.1/32 or 8.8.8.8/24).

## **🛠️ Infrastructure Setup**

### **1. Configure Traefik Access Logs (JSON format)**

Ensure Traefik writes its access logs using the **JSON** format. In your Traefik static configuration file (traefik.yml or CLI options), verify that the following configurations are set:
```
# CLI Flags:  
- "--accesslog=true"  
- "--accesslog.filepath=/logs/access.log"  
- "--accesslog.format=json"
```

### **2. Set Up Proxy Trust (Critical)**

To ensure Traefik correctly extracts and validates proxy chains, you must declare your trusted upstream network layers (such as Cloudflare edge nodes, your local router gateways, or loopback proxies) inside your Traefik configuration file:
```
# Entrypoint config inside traefik.yml  
entryPoints:  
  websecure:  
    address: ":443"  
    forwardedHeaders:  
      trustedIPs:  
        - "127.0.0.1/32"  
        - "10.0.0.0/8"  
        - "172.16.0.0/12"  
        - "192.168.0.0/16"
```
### **3. Adjust Directory Permissions**

Because the container drops root privileges to run under a secure non-root appuser (UID 1000), you must ensure your local data directory is writable by this user ID:

```
sudo chown -R 1000:1000 /home/pranks/docker/npmplus/npmgraf
```

## **🐳 Integration Deployment (docker-compose.yml)**

The complete production-ready stack integrates InfluxDB, Grafana, geoipupdate (automated MaxMind sync), and traefikGrafStats.

This stack exposes no database ports directly to the host machine. Instead, Traefik dynamically routes your domain over a secure reverse_proxy network:

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
      - DOCKER_INFLUXDB_INIT_PASSWORD=hujugotarehuagoru  
      - DOCKER_INFLUXDB_INIT_USERNAME=dhinadhindha  
    hostname: influxdb  
    image: influxdb:2.7-alpine  
    restart: unless-stopped  
    volumes:  
      - type: bind  
        source: /home/pranks/docker/npmplus/influxdbv2/data  
        target: /var/lib/influxdb2  
      - type: bind  
        source: /home/pranks/docker/npmplus/influxdbv2/etc  
        target: /etc/influxdb2  
    networks:  
      - reverse_proxy  
    privileged: false  
    labels:  
      - "traefik.enable=true"  
      - "traefik.http.routers.rpiinflux.rule=Host(`rpiinflux.local.baruah.net`)"  
      - "traefik.http.routers.rpiinflux.entrypoints=web"  
      - "traefik.http.services.rpiinflux-service.loadbalancer.server.port=8086"  
      - "icon=[https://icon.casaos.io/main/all/influxdb.png](https://icon.casaos.io/main/all/influxdb.png)"

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
      - REDIRECTION_LOGS=FALSE  
      - INTERNAL_LOGS=TRUE  
      - MONITORING_LOGS=TRUE  
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
    image: maxmindinc/geoipupdate:latest  
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
### **Local environment Configuration (.env)**

Place your keys and credentials in a local .env file right next to your docker-compose.yml. This file is ignored by Git automatically:

```
# InfluxDB Auth  
INFLUX_TOKEN=INFLUX_TOKEN_KEY

# Maxmind GeoIP Configuration  
GEOIPUPDATE_ACCOUNT_ID=MAXMIND_ID  
GEOIPUPDATE_LICENSE_KEY=MAXMIND_KEY

# Threat Identification  
ABUSEIP_KEY=ABUSEIP_KEY
```

## **📊 Dashboard Import**

Because this application preserves the precise measurement structures, tag names, and coordinates mapped by the original project, existing dashboards are immediately compatible.

To add the map to Grafana:

1. Ensure Grafana is connected to your InfluxDB datasource via **Flux query language** using your organization and bucket settings.  
2. Import your dashboard JSON files using InfluxDBv2 panels targeting ReverseProxyConnections and Redirections measurements.

## **⚖️ License & Attribution**

This program is free software: you can redistribute it and/or modify it under the terms of the **GNU General Public License v3** as published by the Free Software Foundation.

### **Attribution**

* Base project and inspiration: [smilebasti/npmGrafStats](https://github.com/smilebasti/npmGrafStats).
