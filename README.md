# PacketSleuth

PacketSleuth is a Python tool that extracts HTTP requests/responses and geolocates IP addresses from PCAP files. It combines HTTP URL extraction, MaxMind GeoLite2-based geolocation, threat-intelligence lookups, User-Agent analysis, and IOC detection into a single script.

## Features

- **HTTP analysis** — extracts HTTP requests (method, host, path, timestamp, user-agent, referer) and responses (status code, content-type, content-disposition)
- **IP geolocation** — maps every unique IP to a country, city, and coordinates using the MaxMind GeoLite2 City database
- **Malicious IP check** — queries AbuseIPDB or VirusTotal for each IP and marks flagged IPs in red
- **User-Agent analysis** — regex scanner that flags known attack tools (sqlmap, nikto, nmap, Metasploit, brute-forcers, generic automation clients, etc.)
- **IOC extraction** — scans HTTP paths and hostnames for executable downloads, C2 path patterns, SQL injection signatures, encoded payloads, path traversal, and more; supports a custom domain/IP blocklist

## Prerequisites

Geolocation requires a MaxMind GeoLite2 City database file. HTTP analysis and threat intelligence work without it.

To get the database:

1. Sign up for a free MaxMind account at [MaxMind's website](https://www.maxmind.com/en/geolite2/signup).
2. Log in and navigate to the "Download Files" section.
3. Download the **GeoLite2 City** database.
4. Extract the `GeoLite2-City.mmdb` file from the downloaded archive.

For malicious IP checks, obtain a free API key from [AbuseIPDB](https://www.abuseipdb.com/) or [VirusTotal](https://www.virustotal.com/).

## Installation

```bash
pip install -r requirements.txt
```

## Usage

**HTTP analysis only:**

```bash
python pcapIP_geoLocate.py --pcap sample.pcap
```

**HTTP analysis + IP geolocation:**

```bash
python pcapIP_geoLocate.py --pcap sample.pcap --db path/to/GeoLite2-City.mmdb
```

**Full analysis with threat intelligence (AbuseIPDB):**

```bash
python pcapIP_geoLocate.py --pcap sample.pcap --db path/to/GeoLite2-City.mmdb --abuseipdb-key YOUR_KEY
```

**Full analysis with threat intelligence (VirusTotal):**

```bash
python pcapIP_geoLocate.py --pcap sample.pcap --db path/to/GeoLite2-City.mmdb --virustotal-key YOUR_KEY
```

**With a local domain/IP blocklist:**

```bash
python pcapIP_geoLocate.py --pcap sample.pcap --blocklist blocklist.txt
```

### Arguments

| Argument | Required | Description |
|---|---|---|
| `--pcap` | Yes | Path to the PCAP file |
| `--db` | No | Path to the MaxMind GeoLite2 City database (`.mmdb`) |
| `--abuseipdb-key` | No | AbuseIPDB API key for malicious-IP checks |
| `--virustotal-key` | No | VirusTotal API key for malicious-IP checks |
| `--blocklist` | No | Path to a plaintext blocklist file (one domain or IP per line, `#` for comments) |

### Blocklist file format

```
# Known malware domains
evil-c2.example.com
malware-host.net
192.168.1.100
```
