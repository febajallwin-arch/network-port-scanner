"""
cli.py — Command-line interface
Network Port Scanner | Feba J Allwin
"""

import argparse
import sys
import os
import time
import threading
from scanner import PortScanner, ScanResult, PortResult

# ─────────────────────────────────────────────
#  ANSI COLORS
# ─────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BG_RED  = "\033[41m"
    BG_GREEN= "\033[42m"

    @staticmethod
    def disable():
        for attr in ['RESET','BOLD','DIM','RED','GREEN','YELLOW',
                     'BLUE','MAGENTA','CYAN','WHITE','BG_RED','BG_GREEN']:
            setattr(C, attr, "")


# Severity → color
SEV_COLOR = {
    "CRITICAL": C.RED + C.BOLD,
    "HIGH":     C.RED,
    "MEDIUM":   C.YELLOW,
    "LOW":      C.CYAN,
    "INFO":     C.GREEN,
}

BANNER = r"""
  _   _      _                      _    ____
 | \ | | ___| |___      _____  _ __| | _/ ___|  ___ __ _ _ __  _ __   ___ _ __
 |  \| |/ _ \ __\ \ /\ / / _ \| '__| |/ /\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
 | |\  |  __/ |_ \ V  V / (_) | |  |   <  ___) | (_| (_| | | | | | | |  __/ |
 |_| \_|\___|\__| \_/\_/ \___/|_|  |_|\_\|____/ \___\__,_|_| |_|_| |_|\___|_|

  Network Port Scanner v1.0  |  github.com/febajallwin-arch  |  Feba J Allwin
"""


def print_banner():
    print(C.CYAN + BANNER + C.RESET)


def severity_badge(sev: str) -> str:
    color = SEV_COLOR.get(sev, C.WHITE)
    return f"{color}[{sev}]{C.RESET}"


def state_badge(state: str) -> str:
    if state == "open":
        return f"{C.GREEN}{C.BOLD}OPEN{C.RESET}"
    elif state == "filtered":
        return f"{C.YELLOW}FILTERED{C.RESET}"
    return f"{C.DIM}CLOSED{C.RESET}"


def port_row(r: PortResult, show_banner: bool = True) -> str:
    svc = f"{C.CYAN}{r.service:<14}{C.RESET}"
    port_str = f"{C.WHITE}{C.BOLD}{r.port:<6}{C.RESET}"
    desc = f"{C.DIM}{r.description[:42]:<44}{C.RESET}"
    lat = f"{C.DIM}{r.latency_ms:>6.1f}ms{C.RESET}"
    sev = severity_badge(r.severity)
    line = f"  {port_str}  {state_badge(r.state):<18}  {svc}  {desc}  {lat}  {sev}"
    if show_banner and r.banner:
        banner_preview = r.banner[:80].replace('\n', ' ').replace('\r', '')
        line += f"\n  {C.DIM}  ╰─ Banner: {banner_preview}{C.RESET}"
    return line


class ProgressBar:
    """Thread-safe terminal progress bar."""

    def __init__(self, total: int, width: int = 40):
        self.total = total
        self.width = width
        self._done = 0
        self._open = 0
        self._lock = threading.Lock()
        self._start = time.time()

    def update(self, done: int, open_count: int):
        with self._lock:
            self._done = done
            self._open = open_count
            self._render()

    def _render(self):
        pct = self._done / self.total if self.total else 0
        filled = int(self.width * pct)
        bar = "█" * filled + "░" * (self.width - filled)
        elapsed = time.time() - self._start
        speed = self._done / elapsed if elapsed > 0 else 0
        eta = (self.total - self._done) / speed if speed > 0 else 0
        sys.stdout.write(
            f"\r  {C.CYAN}[{bar}]{C.RESET} "
            f"{C.WHITE}{pct*100:5.1f}%{C.RESET}  "
            f"{C.GREEN}{self._done}/{self.total}{C.RESET} ports  "
            f"{C.YELLOW}{self._open} open{C.RESET}  "
            f"{C.DIM}{speed:.0f} p/s  ETA {eta:.0f}s{C.RESET}   "
        )
        sys.stdout.flush()


def run_scan(args):
    print_banner()

    # ── Validate target
    target = args.target.strip()

    # ── Build port range
    if args.ports == "common":
        port_range = (1, 1024)
    elif args.ports == "all":
        port_range = (1, 65535)
    elif "-" in args.ports:
        try:
            lo, hi = args.ports.split("-")
            port_range = (int(lo), int(hi))
        except ValueError:
            print(f"{C.RED}[!] Invalid port range: {args.ports}{C.RESET}")
            sys.exit(1)
    elif "," in args.ports:
        # Comma-separated: scan specific ports only
        try:
            specific = [int(p.strip()) for p in args.ports.split(",")]
            port_range = (min(specific), max(specific))
        except ValueError:
            print(f"{C.RED}[!] Invalid port list: {args.ports}{C.RESET}")
            sys.exit(1)
    else:
        try:
            p = int(args.ports)
            port_range = (p, p)
        except ValueError:
            print(f"{C.RED}[!] Invalid port specification: {args.ports}{C.RESET}")
            sys.exit(1)

    total_ports = port_range[1] - port_range[0] + 1

    print(f"  {C.BOLD}Target   {C.RESET}: {C.CYAN}{target}{C.RESET}")
    print(f"  {C.BOLD}Ports    {C.RESET}: {port_range[0]} – {port_range[1]} ({total_ports:,} ports)")
    print(f"  {C.BOLD}Threads  {C.RESET}: {args.threads}")
    print(f"  {C.BOLD}Timeout  {C.RESET}: {args.timeout}s per port")
    print(f"  {C.BOLD}Banners  {C.RESET}: {'yes' if not args.no_banner else 'no'}")
    print()

    # ── Progress tracking
    pbar = ProgressBar(total_ports)
    open_count = [0]
    discovered = []

    def on_progress(scanned: int, result: PortResult):
        if result.state == "open":
            open_count[0] += 1
            discovered.append(result)
            # Print open port immediately above progress bar
            sys.stdout.write("\r" + " " * 100 + "\r")
            print(port_row(result, show_banner=not args.no_banner))
        pbar.update(scanned, open_count[0])

    print(f"  {C.BOLD}{C.CYAN}{'PORT':<6}  {'STATE':<10}  {'SERVICE':<14}  {'DESCRIPTION':<44}  {'LATENCY':>9}  SEVERITY{C.RESET}")
    print(f"  {'─'*6}  {'─'*10}  {'─'*14}  {'─'*44}  {'─'*9}  {'─'*10}")

    # ── Run scanner
    try:
        scanner = PortScanner(
            target=target,
            port_range=port_range,
            threads=args.threads,
            timeout=args.timeout,
            grab_banners=not args.no_banner,
            callback=on_progress,
        )
    except ValueError as e:
        print(f"\n{C.RED}[!] {e}{C.RESET}")
        sys.exit(1)

    result = scanner.scan()

    # Clear progress bar
    sys.stdout.write("\r" + " " * 120 + "\r")
    print()

    # ── Summary
    print(f"  {'─'*100}")
    print(f"\n  {C.BOLD}SCAN COMPLETE{C.RESET}")
    print(f"  {'─'*100}")
    print(f"  {C.BOLD}Host       {C.RESET}: {result.ip}  ({result.hostname})")
    print(f"  {C.BOLD}OS Hint    {C.RESET}: {result.os_hint}")
    print(f"  {C.BOLD}Duration   {C.RESET}: {result.duration_sec}s")
    print(f"  {C.BOLD}Total ports{C.RESET}: {result.total_ports:,}")
    print(f"  {C.BOLD}Open       {C.RESET}: {C.GREEN}{C.BOLD}{len(result.open_ports)}{C.RESET}")
    print(f"  {C.BOLD}Closed     {C.RESET}: {result.closed_count:,}")
    print(f"  {C.BOLD}Filtered   {C.RESET}: {result.filtered_count:,}")

    # Risk summary
    crits = [r for r in result.open_ports if r.severity == "CRITICAL"]
    highs = [r for r in result.open_ports if r.severity == "HIGH"]
    if crits:
        print(f"\n  {C.RED}{C.BOLD}⚠  CRITICAL RISK ports: {', '.join(str(r.port) for r in crits)}{C.RESET}")
    if highs:
        print(f"  {C.YELLOW}⚠  HIGH RISK ports: {', '.join(str(r.port) for r in highs)}{C.RESET}")

    # ── Export
    if args.output:
        from reporter import Reporter
        ext = os.path.splitext(args.output)[1].lower()
        if ext == ".json":
            Reporter.to_json(result, args.output)
        elif ext == ".csv":
            Reporter.to_csv(result, args.output)
        elif ext == ".html":
            Reporter.to_html(result, args.output)
        elif ext == ".txt":
            Reporter.to_txt(result, args.output)
        else:
            Reporter.to_txt(result, args.output)
        print(f"\n  {C.GREEN}[+] Report saved → {args.output}{C.RESET}")

    print()
    return result


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netscan",
        description="Network Port Scanner — Multithreaded TCP scanner by Feba J Allwin",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py scanme.nmap.org
  python cli.py 192.168.1.1 -p 1-1024
  python cli.py 10.0.0.1 -p all -t 500
  python cli.py example.com -p 80,443,8080 -o report.html
  python cli.py 192.168.1.0/24 --no-banner -o results.json
        """
    )
    p.add_argument("target", help="Target hostname, IP, or CIDR range")
    p.add_argument(
        "-p", "--ports",
        default="common",
        metavar="PORTS",
        help="Port spec: 'common' (1-1024), 'all' (1-65535), '80-443', '22,80,443' (default: common)"
    )
    p.add_argument(
        "-t", "--threads",
        type=int, default=200,
        metavar="N",
        help="Worker threads (default: 200, max: 1000)"
    )
    p.add_argument(
        "--timeout",
        type=float, default=1.0,
        metavar="SEC",
        help="Per-port timeout in seconds (default: 1.0)"
    )
    p.add_argument(
        "--no-banner",
        action="store_true",
        help="Skip banner grabbing (faster)"
    )
    p.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save report: report.html / report.json / report.csv / report.txt"
    )
    p.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colors (for piping/logging)"
    )
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.no_color or not sys.stdout.isatty():
        C.disable()

    # Clamp threads
    args.threads = max(1, min(args.threads, 1000))

    run_scan(args)


if __name__ == "__main__":
    main()