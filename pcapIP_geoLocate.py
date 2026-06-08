import argparse
import datetime
import ipaddress
import re
import sys

import requests
from scapy.all import rdpcap
from scapy.layers.inet import IP
from scapy.layers import http
from geoip2.database import Reader
from tabulate import tabulate

# ANSI colours
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── User-Agent suspicious patterns ───────────────────────────────────────────

_UA_PATTERNS = [
    (re.compile(r"sqlmap",                          re.I), "SQLi scanner (sqlmap)"),
    (re.compile(r"\bnmap\b",                        re.I), "Port scanner (nmap)"),
    (re.compile(r"nikto",                           re.I), "Web scanner (Nikto)"),
    (re.compile(r"masscan",                         re.I), "Port scanner (masscan)"),
    (re.compile(r"zgrab",                           re.I), "Banner grabber (zgrab)"),
    (re.compile(r"dirbuster|gobuster|dirb\b|wfuzz|ffuf", re.I), "Directory brute-forcer"),
    (re.compile(r"hydra|medusa|brutus",             re.I), "Credential brute-forcer"),
    (re.compile(r"metasploit",                      re.I), "Metasploit framework"),
    (re.compile(r"acunetix|appscan|burpsuite|havij",re.I), "Vulnerability scanner"),
    (re.compile(r"python-requests/",                re.I), "Generic automation (python-requests)"),
    (re.compile(r"^(curl|wget)/",                   re.I), "CLI downloader (possible scripted fetch)"),
    (re.compile(r"go-http-client",                  re.I), "Generic Go HTTP client"),
    (re.compile(r"libwww-perl",                     re.I), "Perl HTTP client (common in scanners)"),
    (re.compile(r"java/\d",                         re.I), "Raw Java HTTP client"),
]

# ── IOC patterns ──────────────────────────────────────────────────────────────

_IOC_PATTERNS = [
    (re.compile(r"\.(exe|bat|ps1|vbs|cmd|msi|dll|scr|hta|jar|sh|elf)(\?|$)", re.I),
     "Executable/payload download"),
    (re.compile(r"(eval|base64_decode|cmd|shell|exec|system|passthru|assert)\s*[\(%=]", re.I),
     "Suspicious server-side function in URL"),
    (re.compile(r"/(gate|panel|c2|bot|payload|dropper|beacon|implant|stager|loader)(\.php|\.asp|/|$)", re.I),
     "Known C2/malware path keyword"),
    (re.compile(r"(UNION\s+SELECT|OR\s+1=1|DROP\s+TABLE|SLEEP\s*\(|BENCHMARK\s*\()", re.I),
     "SQL injection pattern"),
    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
     "Long base64-like blob in URL (possible encoded payload)"),
    (re.compile(r"(%00|\.\.%2[Ff]|%2[Ee]%2[Ee])"),
     "Path traversal / null-byte encoding"),
    (re.compile(r"(%3[Cc]script|javascript:|vbscript:)", re.I),
     "Encoded XSS / script-injection attempt"),
]

# ── Reputation cache & helpers ────────────────────────────────────────────────

_rep_cache: dict = {}


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def check_abuseipdb(ip: str, api_key: str) -> dict:
    if ip in _rep_cache:
        return _rep_cache[ip]
    if _is_private(ip):
        result = {"malicious": False, "label": "private", "source": "abuseipdb"}
        _rep_cache[ip] = result
        return result
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": "90"},
            timeout=8,
        )
        data = resp.json().get("data", {})
        score   = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        malicious = score > 0 or reports > 0
        label = f"score={score}, reports={reports}" if malicious else "clean"
        result = {"malicious": malicious, "label": label, "source": "abuseipdb"}
    except Exception as exc:
        result = {"malicious": False, "label": f"lookup error: {exc}", "source": "abuseipdb"}
    _rep_cache[ip] = result
    return result


def check_virustotal(ip: str, api_key: str) -> dict:
    if ip in _rep_cache:
        return _rep_cache[ip]
    if _is_private(ip):
        result = {"malicious": False, "label": "private", "source": "virustotal"}
        _rep_cache[ip] = result
        return result
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key},
            timeout=8,
        )
        stats    = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious_votes = stats.get("malicious", 0)
        malicious = malicious_votes > 0
        label = f"malicious votes={malicious_votes}" if malicious else "clean"
        result = {"malicious": malicious, "label": label, "source": "virustotal"}
    except Exception as exc:
        result = {"malicious": False, "label": f"lookup error: {exc}", "source": "virustotal"}
    _rep_cache[ip] = result
    return result


def reputation_tag(ip: str, abuseipdb_key=None, virustotal_key=None) -> str:
    rep = None
    if abuseipdb_key:
        rep = check_abuseipdb(ip, abuseipdb_key)
    elif virustotal_key:
        rep = check_virustotal(ip, virustotal_key)
    if rep is None or rep["label"] in ("private", "clean"):
        return ""
    return f" {RED}[MALICIOUS via {rep['source']}: {rep['label']}]{RESET}"


def reputation_cell(ip: str, abuseipdb_key=None, virustotal_key=None) -> str:
    rep = None
    if abuseipdb_key:
        rep = check_abuseipdb(ip, abuseipdb_key)
    elif virustotal_key:
        rep = check_virustotal(ip, virustotal_key)
    if rep is None:
        return ""
    if rep["label"] == "private":
        return "private"
    if rep["malicious"]:
        return f"{RED}MALICIOUS ({rep['label']}){RESET}"
    return f"{GREEN}clean{RESET}"


# ── User-Agent analysis ───────────────────────────────────────────────────────

def analyze_user_agent(ua: str) -> tuple[bool, str]:
    if not ua or not ua.strip():
        return True, "Empty User-Agent"
    for pattern, reason in _UA_PATTERNS:
        if pattern.search(ua):
            return True, reason
    return False, ""


# ── IOC scan ─────────────────────────────────────────────────────────────────

def scan_ioc(host: str, path: str, blocklist: set) -> list[str]:
    findings = []
    clean_host = host.lower().lstrip("www.")
    if host.lower() in blocklist or clean_host in blocklist:
        findings.append(f"Domain on blocklist: {host}")
    url = host + path
    for pattern, reason in _IOC_PATTERNS:
        if pattern.search(url):
            findings.append(reason)
    return findings


def load_blocklist(path: str) -> set:
    try:
        with open(path) as f:
            return {line.strip().lower() for line in f if line.strip() and not line.startswith("#")}
    except Exception as exc:
        print(f"{YELLOW}Warning: could not load blocklist {path}: {exc}{RESET}")
        return set()


# ── HTTP extraction ───────────────────────────────────────────────────────────

def extract_http(packets, abuseipdb_key=None, virustotal_key=None, blocklist=None):
    if blocklist is None:
        blocklist = set()

    for p in packets:
        if "HTTPRequest" in p:
            ip_layer = p["IP"]
            req       = p["HTTPRequest"]
            timestamp = datetime.datetime.utcfromtimestamp(int(p.time)).strftime("%Y-%m-%d %H:%M:%S UTC")

            host    = req.Host.decode()        if req.Host        else ""
            path    = req.Path.decode()        if req.Path        else "/"
            method  = req.Method.decode()      if req.Method      else "?"
            ua      = req.User_Agent.decode()  if req.User_Agent  else ""
            referer = req.Referer.decode()     if req.Referer     else "None"
            src_ip  = ip_layer.src
            dst_ip  = ip_layer.dst

            rep = reputation_tag(src_ip, abuseipdb_key, virustotal_key)
            print(
                f"\n{BOLD}{src_ip}:{ip_layer.sport}{RESET}{rep} → "
                f"{BOLD}{method} {host}{path}{RESET} at {timestamp} "
                f"({dst_ip}:{ip_layer.dport})"
            )

            ua_bad, ua_reason = analyze_user_agent(ua)
            ua_line = f"  User-Agent: {ua or '(empty)'}"
            if ua_bad:
                print(f"{RED}{ua_line}  ← SUSPICIOUS: {ua_reason}{RESET}")
            else:
                print(ua_line)

            print(f"  Referer: {referer}")

            for ioc in scan_ioc(host, path, blocklist):
                print(f"  {RED}[IOC] {ioc}{RESET}")

        if "HTTPResponse" in p:
            resp   = p["HTTPResponse"]
            status = resp.Status_Code.decode()        if resp.Status_Code        else "?"
            ctype  = resp.Content_Type.decode()       if resp.Content_Type        else "?"
            disp   = resp.Content_Disposition.decode() if resp.Content_Disposition else "None"
            color  = RED if status[:1] in ("4", "5") else RESET
            print(f"  Response: {color}{status}{RESET}  Content-Type: {ctype}  Disposition: {disp}")

    print("\nDone. End of pcap")


# ── Geolocation ───────────────────────────────────────────────────────────────

def get_geolocation(ip_addr, reader):
    try:
        r = reader.city(ip_addr)
        return (
            r.country.name or "Unknown",
            r.city.name    or "Unknown",
            r.location.latitude,
            r.location.longitude,
        )
    except Exception:
        return "INVALID", "INVALID", None, None


def extract_and_geolocate(packets, db_path, abuseipdb_key=None, virustotal_key=None):
    ip_addresses = {p[IP].src for p in packets if IP in p} | {p[IP].dst for p in packets if IP in p}
    if not ip_addresses:
        print("No IP addresses found in the PCAP file.")
        return

    use_rep = bool(abuseipdb_key or virustotal_key)
    print(f"\nGeolocating {len(ip_addresses)} unique IPs"
          + (" + checking reputation..." if use_rep else "..."))

    results = []
    try:
        with Reader(db_path) as reader:
            for ip in ip_addresses:
                country, city, lat, lon = get_geolocation(ip, reader)
                row = [ip, country, city, lat, lon]
                if use_rep:
                    row.append(reputation_cell(ip, abuseipdb_key, virustotal_key))
                results.append(row)
    except Exception as exc:
        print(f"Error opening database: {exc}")
        sys.exit(1)

    headers = ["IP Address", "Country", "City", "Latitude", "Longitude"]
    if use_rep:
        headers.append("Reputation")
    print(tabulate(results, headers=headers, tablefmt="grid"))


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="PacketSleuth: PCAP forensics — HTTP analysis, geolocation, and threat intelligence"
    )
    parser.add_argument("--pcap",           required=True, metavar="FILE",
                        help="Path to the PCAP file")
    parser.add_argument("--db",             metavar="FILE",
                        help="MaxMind GeoLite2 City database (.mmdb)")
    parser.add_argument("--abuseipdb-key",  metavar="KEY",
                        help="AbuseIPDB API key for malicious-IP checks")
    parser.add_argument("--virustotal-key", metavar="KEY",
                        help="VirusTotal API key for malicious-IP checks")
    parser.add_argument("--blocklist",      metavar="FILE",
                        help="Plaintext blocklist file (one domain or IP per line)")
    args = parser.parse_args()

    blocklist = load_blocklist(args.blocklist) if args.blocklist else set()

    try:
        packets = rdpcap(args.pcap)
    except Exception as exc:
        print(f"Error reading PCAP file: {exc}")
        sys.exit(1)

    print("--- HTTP Requests/Responses ---")
    extract_http(
        packets,
        abuseipdb_key=args.abuseipdb_key,
        virustotal_key=args.virustotal_key,
        blocklist=blocklist,
    )

    if args.db:
        print("\n--- IP Geolocation ---")
        extract_and_geolocate(
            packets,
            args.db,
            abuseipdb_key=args.abuseipdb_key,
            virustotal_key=args.virustotal_key,
        )


if __name__ == "__main__":
    main()
