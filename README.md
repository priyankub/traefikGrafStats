traefikGrafStats 📈

A platform-agnostic, lightweight, and highly performant parser that tails Traefik access logs in JSON format, resolves client IP geolocation coordinates, queries AbuseIPDB scores, and pushes real-time analytical traffic metrics straight into an InfluxDB v2 database.

This project is a complete architectural rewrite of the exceptional npmGrafStats utility, swapping out Nginx regex line parsing for native, high-speed Traefik JSON log streaming.

🚀 Key Features

Native Traefik JSON Log Parsing: Direct key extraction out of structured JSON files—fast, highly reliable, and immune to regex formatting breakages.

Platform-Agnostic Build: Multi-arch Docker images built for linux/amd64 and linux/arm64 (fully optimized for the Raspberry Pi 5).

Direct Geolocation Lookup: Integrates with Maxmind's GeoLite2 databases to find the city, state, country, and ASN of incoming traffic.

AbuseIPDB Integration: Cross-references incoming IPs against malicious reporting API registries.

Seamless InfluxDB v2 & Grafana Compatibility: Preserves the metric schemas and tags from npmGrafStats, ensuring absolute drop-in compatibility with your existing Grafana dashboards.

🛠️ Configuration Requirements

1. Configure Traefik Access Logs (JSON Format)

To feed structured data to the parser, you must configure Traefik to output its access logs in JSON. Add these commands (or equivalent file provider variables) to your Traefik deployment:

# In your traefik service commands:
- "--accesslog=true"
- "--accesslog.filepath=/logs/access.log"
- "--accesslog.format=json"


2. Prepare Directories on your Host Machine

The application requires direct access to your Traefik log directory, your InfluxDB database state, and a folder to store Maxmind's GeoIP DB cache files:

mkdir -p ./traefik_logs
mkdir -p ./geolite
mkdir -p ./npmgraf_data


Ensure the container has permission to write to your npmgraf_data folder (needed to initialize the SQLite API cache database):

sudo chown -R 1000:1000 ./npmgraf_data


🐳 Integration Deployment (docker-compose.yml)

Here is a secure production deployment file. Note that no host ports are exposed directly; instead, we expose the InfluxDB management console strictly over the internal secure reverse_proxy network using Traefik labels:

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
      - ./influxdbv2/data:/var/lib/influxdb2
      - ./influxdbv2/etc:/etc/influxdb2
    networks:
      - reverse_proxy
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.rpiinflux.rule=Host(`rpiinflux.local.baruah.net`)"
      - "traefik.http.routers.rpiinflux.middlewares=https-redirect@file, default-headers@file"      
      - "traefik.http.routers.rpiinflux.entrypoints=https"
      - "traefik.http.routers.rpiinflux.tls=true"
      - "traefik.http.services.rpiinflux.loadbalancer.server.port=8086"
      - "traefik.http.services.rpiinflux.loadbalancer.server.scheme=http"

  traefikgraf:
    container_name: traefikgraf
    image: ghcr.io/yourusername/traefikgrafstats:latest
    restart: unless-stopped
    environment:
      - ABUSEIP_KEY=2a22ae411e4e5c7557f98b8899a2639aa747f6536e1e52618421353f2ecc4df4b598b558315ddd87
      - INFLUX_HOST=http://influxdb:8086
      - INFLUX_ORG=npmgrafstats
      - INFLUX_BUCKET=npmgrafstats
      - INFLUX_TOKEN=your-token-goes-here
      - INTERNAL_LOGS=true
      - MONITORING_LOGS=true
    hostname: traefikgraf
    volumes:
      - type: bind
        source: /home/pranks/docker/traefik/log # Traefik access.log path
        target: /logs
      - ./geolite:/geolite
      - ./npmgraf_data:/data
    networks:
      - reverse_proxy
    depends_on:
      - influxdb

  geoipupdate:
    cpu_shares: 90
    container_name: geoipupdate
    environment:
      - GEOIPUPDATE_ACCOUNT_ID=your_maxmind_id
      - GEOIPUPDATE_EDITION_IDS=GeoLite2-Country GeoLite2-City GeoLite2-ASN
      - GEOIPUPDATE_FREQUENCY=24
      - GEOIPUPDATE_LICENSE_KEY=your_maxmind_key
      - TZ=America/Chicago
    hostname: geoipupdate
    image: ghcr.io/maxmind/geoipupdate:latest
    restart: always
    volumes:
      - ./geolite:/usr/share/GeoIP
    networks:
      - reverse_proxy

networks:
  reverse_proxy:
    external: true


📊 Dashboards and Visualizations

Since traefikGrafStats perfectly mirrors the tag and measurement schemas used in npmGrafStats, you can import the preconfigured community dashboards directly into your Grafana instance.

Map Dashboard (with Filter): Import original template maps from your repository or using standard InfluxDBv2 panels pointing to your measurement queries.

⚖️ License & Attribution

This project is licensed under the GNU General Public License v3 (GPL v3).

Credits & Attribution

This project is an independent derivative of smilebasti/npmGrafStats. Huge thank you to the original contributors for building the foundation of this monitoring pipeline.
