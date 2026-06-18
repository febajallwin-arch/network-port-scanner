"""
scanner.py — Core scanning engine
Network Port Scanner | Feba J Allwin
Multithreaded TCP/IP scanner with service fingerprinting
"""

import socket
import threading
import queue
import time
import struct
import ipaddress
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────
#  SERVICE FINGERPRINT DATABASE (20+ protocols)
# ─────────────────────────────────────────────
SERVICE_DB = {
    20:   ("FTP-DATA",  "File Transfer Protocol - Data"),
    21:   ("FTP",       "File Transfer Protocol"),
    22:   ("SSH",       "Secure Shell"),
    23:   ("TELNET",    "Telnet Protocol"),
    25:   ("SMTP",      "Simple Mail Transfer Protocol"),
    53:   ("DNS",       "Domain Name System"),
    67:   ("DHCP",      "Dynamic Host Configuration Protocol"),
    68:   ("DHCP",      "DHCP Client"),
    69:   ("TFTP",      "Trivial File Transfer Protocol"),
    80:   ("HTTP",      "HyperText Transfer Protocol"),
    110:  ("POP3",      "Post Office Protocol v3"),
    111:  ("RPC",       "Remote Procedure Call"),
    119:  ("NNTP",      "Network News Transfer Protocol"),
    123:  ("NTP",       "Network Time Protocol"),
    135:  ("MSRPC",     "Microsoft RPC"),
    137:  ("NETBIOS",   "NetBIOS Name Service"),
    139:  ("NETBIOS",   "NetBIOS Session Service"),
    143:  ("IMAP",      "Internet Message Access Protocol"),
    161:  ("SNMP",      "Simple Network Management Protocol"),
    194:  ("IRC",       "Internet Relay Chat"),
    389:  ("LDAP",      "Lightweight Directory Access Protocol"),
    443:  ("HTTPS",     "HTTP Secure / TLS"),
    445:  ("SMB",       "Server Message Block"),
    465:  ("SMTPS",     "SMTP Secure"),
    514:  ("SYSLOG",    "System Logging Protocol"),
    515:  ("LPD",       "Line Printer Daemon"),
    587:  ("SUBMISSION","Mail Submission Agent"),
    631:  ("IPP",       "Internet Printing Protocol"),
    636:  ("LDAPS",     "LDAP over SSL"),
    993:  ("IMAPS",     "IMAP over SSL"),
    995:  ("POP3S",     "POP3 over SSL"),
    1080: ("SOCKS",     "SOCKS Proxy"),
    1194: ("OpenVPN",   "OpenVPN"),
    1433: ("MSSQL",     "Microsoft SQL Server"),
    1521: ("Oracle",    "Oracle Database"),
    1723: ("PPTP",      "Point-to-Point Tunneling Protocol"),
    2049: ("NFS",       "Network File System"),
    2181: ("ZooKeeper", "Apache ZooKeeper"),
    2375: ("Docker",    "Docker Daemon (unencrypted)"),
    2376: ("Docker-TLS","Docker Daemon (TLS)"),
    3000: ("Dev-HTTP",  "Development HTTP Server"),
    3306: ("MySQL",     "MySQL Database"),
    3389: ("RDP",       "Remote Desktop Protocol"),
    4444: ("Metasploit","Metasploit Framework Default"),
    5000: ("Flask",     "Python Flask Dev Server"),
    5432: ("PostgreSQL","PostgreSQL Database"),
    5900: ("VNC",       "Virtual Network Computing"),
    5984: ("CouchDB",   "Apache CouchDB"),
    6379: ("Redis",     "Redis In-Memory Store"),
    6443: ("Kubernetes","Kubernetes API Server"),
    7001: ("WebLogic",  "Oracle WebLogic Server"),
    8000: ("HTTP-Alt",  "Alternative HTTP Server"),
    8080: ("HTTP-Proxy","HTTP Proxy / Alt Web Server"),
    8443: ("HTTPS-Alt", "Alternative HTTPS Server"),
    8888: ("Jupyter",   "Jupyter Notebook"),
    9000: ("SonarQube", "SonarQube / PHP-FPM"),
    9092: ("Kafka",     "Apache Kafka Broker"),
    9200: ("Elasticsearch","Elasticsearch REST API"),
    9300: ("ES-Cluster","Elasticsearch Cluster"),
    11211:("Memcached", "Memcached"),
    27017:("MongoDB",   "MongoDB Database"),
    27018:("MongoDB",   "MongoDB Shard"),
    50000:("DB2",       "IBM DB2 Database"),
}

# Banner grab probes for active fingerprinting
BANNER_PROBES = {
    "HTTP":  b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    "FTP":   b"",
    "SSH":   b"",
    "SMTP":  b"EHLO scanner\r\n",
    "default": b"",
}

SEVERITY_MAP = {
    # Critical — known dangerous open ports
    "Metasploit": "CRITICAL",
    "Telnet": "HIGH",
    "NETBIOS": "HIGH",
    "SMB": "HIGH",
    "RDP": "MEDIUM",
    "Docker": "CRITICAL",
    "Redis": "HIGH",
    "MongoDB": "HIGH",
    "Elasticsearch": "HIGH",
    "Memcached": "HIGH",
    "FTP": "MEDIUM",
    "SNMP": "MEDIUM",
}


@dataclass
class PortResult:
    port: int
    state: str          # open / closed / filtered
    service: str = "Unknown"
    description: str = ""
    banner: str = ""
    latency_ms: float = 0.0
    severity: str = "INFO"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "state": self.state,
            "service": self.service,
            "description": self.description,
            "banner": self.banner[:200] if self.banner else "",
            "latency_ms": round(self.latency_ms, 2),
            "severity": self.severity,
            "timestamp": self.timestamp,
        }


@dataclass
class ScanResult:
    target: str
    ip: str
    start_time: str
    end_time: str = ""
    duration_sec: float = 0.0
    total_ports: int = 0
    open_ports: list = field(default_factory=list)
    closed_count: int = 0
    filtered_count: int = 0
    os_hint: str = "Unknown"
    hostname: str = ""


class PortScanner:
    """
    Multithreaded TCP connect scanner with:
    - Service fingerprinting via port database
    - Active banner grabbing
    - OS detection hints (TTL-based)
    - Concurrent scanning via thread pool
    - Real-time progress reporting
    """

    def __init__(
        self,
        target: str,
        port_range: tuple = (1, 1024),
        threads: int = 200,
        timeout: float = 1.0,
        grab_banners: bool = True,
        callback=None,
    ):
        self.target = target
        self.port_range = port_range
        self.threads = threads
        self.timeout = timeout
        self.grab_banners = grab_banners
        self.callback = callback  # progress(port, result)

        self._queue = queue.Queue()
        self._results: list[PortResult] = []
        self._lock = threading.Lock()
        self._scanned = 0
        self._stop_event = threading.Event()

        # Resolve target
        try:
            self.ip = socket.gethostbyname(target)
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve host '{target}': {e}")

        try:
            self.hostname = socket.gethostbyaddr(self.ip)[0]
        except socket.herror:
            self.hostname = target

    # ─────────────────────────────────────────
    #  CORE SCAN
    # ─────────────────────────────────────────

    def scan(self) -> ScanResult:
        start = time.time()
        start_ts = datetime.now().isoformat()

        total = self.port_range[1] - self.port_range[0] + 1

        # Fill the queue
        for port in range(self.port_range[0], self.port_range[1] + 1):
            self._queue.put(port)

        # Spawn worker threads
        workers = []
        for _ in range(min(self.threads, total)):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            workers.append(t)

        # Wait for all threads
        self._queue.join()
        self._stop_event.set()
        for t in workers:
            t.join(timeout=2)

        end = time.time()

        open_results = sorted(
            [r for r in self._results if r.state == "open"],
            key=lambda r: r.port
        )
        closed = sum(1 for r in self._results if r.state == "closed")
        filtered = sum(1 for r in self._results if r.state == "filtered")

        return ScanResult(
            target=self.target,
            ip=self.ip,
            start_time=start_ts,
            end_time=datetime.now().isoformat(),
            duration_sec=round(end - start, 2),
            total_ports=total,
            open_ports=open_results,
            closed_count=closed,
            filtered_count=filtered,
            hostname=self.hostname,
            os_hint=self._os_hint(),
        )

    # ─────────────────────────────────────────
    #  WORKER
    # ─────────────────────────────────────────

    def _worker(self):
        while not self._stop_event.is_set():
            try:
                port = self._queue.get(timeout=0.5)
            except queue.Empty:
                break
            result = self._scan_port(port)
            with self._lock:
                self._results.append(result)
                self._scanned += 1
            if self.callback:
                self.callback(self._scanned, result)
            self._queue.task_done()

    # ─────────────────────────────────────────
    #  PORT SCAN + FINGERPRINT
    # ─────────────────────────────────────────

    def _scan_port(self, port: int) -> PortResult:
        t0 = time.time()
        state = "closed"
        banner = ""

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                code = sock.connect_ex((self.ip, port))
                latency = (time.time() - t0) * 1000

                if code == 0:
                    state = "open"
                    if self.grab_banners:
                        banner = self._grab_banner(sock, port)
                elif code in (111, 10061):  # ECONNREFUSED
                    state = "closed"
                else:
                    state = "filtered"

        except socket.timeout:
            latency = (time.time() - t0) * 1000
            state = "filtered"
        except OSError:
            latency = (time.time() - t0) * 1000
            state = "closed"

        service, description = SERVICE_DB.get(port, ("Unknown", "Unregistered Port"))
        severity = SEVERITY_MAP.get(service, "INFO") if state == "open" else "INFO"

        # Check banner for additional service clues
        if banner and service == "Unknown":
            service, description = self._fingerprint_banner(banner)

        return PortResult(
            port=port,
            state=state,
            service=service,
            description=description,
            banner=banner,
            latency_ms=latency,
            severity=severity,
        )

    # ─────────────────────────────────────────
    #  BANNER GRABBING
    # ─────────────────────────────────────────

    def _grab_banner(self, sock: socket.socket, port: int) -> str:
        try:
            sock.settimeout(1.5)
            # Send probe based on known service
            service = SERVICE_DB.get(port, ("Unknown",))[0]
            probe = BANNER_PROBES.get(service, BANNER_PROBES["default"])
            if probe:
                sock.sendall(probe)
            # Try to receive banner
            data = sock.recv(1024)
            return data.decode("utf-8", errors="replace").strip()
        except Exception:
            return ""

    # ─────────────────────────────────────────
    #  BANNER FINGERPRINTING
    # ─────────────────────────────────────────

    def _fingerprint_banner(self, banner: str) -> tuple[str, str]:
        b = banner.lower()
        if "ssh" in b:
            return "SSH", "Secure Shell (banner detected)"
        if "http" in b or "html" in b:
            return "HTTP", "HyperText Transfer Protocol (banner detected)"
        if "smtp" in b or "220" in b:
            return "SMTP", "Mail Transfer Protocol (banner detected)"
        if "ftp" in b:
            return "FTP", "File Transfer Protocol (banner detected)"
        if "mysql" in b:
            return "MySQL", "MySQL Database (banner detected)"
        if "redis" in b:
            return "Redis", "Redis In-Memory Store (banner detected)"
        if "mongodb" in b:
            return "MongoDB", "MongoDB Database (banner detected)"
        return "Unknown", "Unidentified Service"

    # ─────────────────────────────────────────
    #  OS HINT (TTL-based heuristic)
    # ─────────────────────────────────────────

    def _os_hint(self) -> str:
        """Estimate OS from ICMP TTL (best effort, not guaranteed)."""
        try:
            import subprocess, platform
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["ping", "-n", "1", self.ip],
                    timeout=3, stderr=subprocess.DEVNULL, text=True
                )
            else:
                out = subprocess.check_output(
                    ["ping", "-c", "1", "-W", "2", self.ip],
                    timeout=3, stderr=subprocess.DEVNULL, text=True
                )
            if "ttl=64" in out.lower() or "ttl=63" in out.lower():
                return "Linux / macOS (TTL≈64)"
            elif "ttl=128" in out.lower() or "ttl=127" in out.lower():
                return "Windows (TTL≈128)"
            elif "ttl=255" in out.lower():
                return "Network Device / Cisco (TTL≈255)"
        except Exception:
            pass
        return "Unknown"