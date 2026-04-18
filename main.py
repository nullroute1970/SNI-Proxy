"""
main.py - Entry point for the SNI Spoofing proxy.

This module implements an asynchronous TCP proxy server that:
1. Listens for incoming local connections (e.g., from a browser or client app).
2. Establishes outgoing connections to the target server.
3. During the TCP handshake, injects a fake TLS ClientHello with a spoofed SNI
   (Server Name Indication) to bypass DPI (Deep Packet Inspection) filtering.
4. After the handshake bypass, relays data bidirectionally between client and server.

The fake ClientHello is sent with a deliberately wrong TCP sequence number so the
real server ignores it, but the DPI middlebox sees the allowed SNI and lets the
connection through.
"""

import asyncio
import concurrent.futures
import ctypes
import dataclasses
import datetime
import json
import logging
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import ipaddress
import tomllib


def _is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except AttributeError:
        return False


def _relaunch_as_admin() -> None:
    """Re-launch the current process with UAC elevation and exit the current process."""
    if getattr(sys, 'frozen', False):
        # Running as a PyInstaller EXE — sys.executable IS the EXE; no script path needed.
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params or None, None, 1
        )
    else:
        # Running as a plain Python script.
        executable = sys.executable
        script = os.path.abspath(sys.argv[0])
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", executable, f'"{script}" {params}', None, 1
        )
    sys.exit(0)


if not _is_admin():
    _relaunch_as_admin()

from rich.console import Console
from rich.logging import RichHandler
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.live import Live
from rich.text import Text
from rich.columns import Columns
from rich.align import Align
from rich import box

from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector
from metrics import metrics

# Shared console instance — used by all output and the live dashboard
console = Console()

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    handlers=[RichHandler(console=console, show_path=False, markup=False, rich_tracebacks=True)],
)
logger = logging.getLogger(__name__)

# ----- Per-Run Log File -----
# Set by _setup_file_logging() at startup; kept open for the duration of the session.
_log_file = None  # TextIOWrapper when active, None until _setup_file_logging() runs
_log_file_path: str | None = None


def _setup_file_logging() -> str:
    """Create the logs/ directory, open a timestamped log file, and attach a FileHandler
    to the root logger so all existing logger.* calls are captured automatically."""
    global _log_file, _log_file_path
    logs_dir = os.path.join(get_exe_dir(), "logs")
    os.makedirs(logs_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_path = os.path.join(logs_dir, f"{timestamp}.log")
    _log_file_path = log_path
    _log_file = open(log_path, "a", encoding="utf-8")  # noqa: WPS515

    # Attach a FileHandler to the root logger so every logger.* call in the app
    # is automatically written to the file without touching any call sites.
    file_handler = logging.FileHandler(log_path, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)-8s %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
    )
    logging.getLogger().addHandler(file_handler)

    # Write a human-readable session header directly to the file.
    _log_file.write(
        f"=== Session started {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===\n\n"
    )
    _log_file.flush()
    return log_path


def _log_scan_results(results: "list[SniResult]", title: str) -> None:
    """Write a plain-text SNI scan result table to the open log file."""
    if _log_file is None:
        return
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    _log_file.write(f"\n=== {title} ({now}) — {len(results)} SNI(s) ===\n")

    col_w = {"sni": 30, "ip": 17, "status": 9, "tls": 5, "latency": 10, "hops": 6, "cdn": 20}
    header = (
        f"{'SNI':<{col_w['sni']}}  {'IP':<{col_w['ip']}}  {'Status':<{col_w['status']}}"
        f"  {'TLS':<{col_w['tls']}}  {'Latency':<{col_w['latency']}}  {'Hops':<{col_w['hops']}}"
        f"  {'CDN':<{col_w['cdn']}}\n"
    )
    separator = "-" * (sum(col_w.values()) + 2 * (len(col_w) - 1)) + "\n"
    _log_file.write(separator)
    _log_file.write(header)
    _log_file.write(separator)

    for r in results:
        if r is None:
            continue
        if r.tls_ok:
            status = "TCP+TLS"
        elif r.tcp_ok:
            status = "TCP"
        elif r.ip is not None and r.tcp_fail_reason in ("timeout", None):
            status = "timeout"
        elif r.ip is not None:
            status = r.tcp_fail_reason or "refused"
        else:
            status = "DNS fail"

        tls = "yes" if r.tls_ok else ("no" if r.tls_ok is False else "-")
        latency = f"{r.latency_ms:.0f} ms" if r.latency_ms is not None else "-"
        hops = str(r.ttl_hops) if r.ttl_hops is not None else "-"
        ip = r.ip or "-"
        cdn = r.cdn or "-"

        _log_file.write(
            f"{r.sni:<{col_w['sni']}}  {ip:<{col_w['ip']}}  {status:<{col_w['status']}}"
            f"  {tls:<{col_w['tls']}}  {latency:<{col_w['latency']}}  {hops:<{col_w['hops']}}"
            f"  {cdn:<{col_w['cdn']}}\n"
        )

    _log_file.write(separator)
    _log_file.flush()


def ensure_firewall_rule(port: int) -> None:
    """Create an inbound TCP allow rule for *port* in Windows Firewall if one does not already exist."""
    rule_name = f"SNI-Proxy-{port}"
    check = subprocess.run(
        ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
        capture_output=True,
        text=True,
    )
    if check.returncode == 0:
        return  # rule already exists
    add = subprocess.run(
        [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=allow",
            "protocol=TCP",
            f"localport={port}",
        ],
        capture_output=True,
        text=True,
    )
    if add.returncode == 0:
        logger.info("Windows Firewall: created inbound TCP allow rule for port %d ('%s').", port, rule_name)
    else:
        logger.warning(
            "Windows Firewall: failed to create rule '%s': %s",
            rule_name,
            (add.stderr or add.stdout).strip(),
        )


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located.
    Handles both PyInstaller-frozen executables and normal Python scripts."""
    if getattr(sys, 'frozen', False):
        # Running as a PyInstaller EXE
        return os.path.dirname(sys.executable)
    else:
        # Running as a normal Python script
        return os.path.dirname(os.path.abspath(__file__))


# ----- Configuration Loading -----
# Build the path to config.toml relative to the executable/script location
config_path = os.path.join(get_exe_dir(), 'config.toml')

# Load the config
with open(config_path, 'rb') as f:
    config = tomllib.load(f)

LISTEN_HOST = config["LISTEN_HOST"]        # Local address to listen on (e.g. 127.0.0.1)
LISTEN_PORT = config["LISTEN_PORT"]        # Local port to listen on
ensure_firewall_rule(LISTEN_PORT)
CONNECT_PORT = config.get("CONNECT_PORT", 443)  # Target server port (default: 443)
DATA_MODE = "tls"           # Data format mode (only TLS is supported)

# These will be set by select_sni_interactive() before the proxy starts
FAKE_SNI_STR: str = ""
FAKE_SNI: bytes = b""
CONNECT_IP: str = ""
INTERFACE_IPV4: str = ""

# DPI bypass configuration
VALID_BYPASS_METHODS = {"wrong_seq", "wrong_checksum", "low_ttl", "tcp_segmentation", "duplicate_syn",
                        "ip_fragmentation", "fake_rst", "tls_record_frag", "tcp_urgent_pointer"}
BYPASS_METHOD = config.get("BYPASS_METHOD", "wrong_seq")
if BYPASS_METHOD not in VALID_BYPASS_METHODS:
    logger.critical("Unknown BYPASS_METHOD '%s'. Valid options: %s",
                    BYPASS_METHOD, ', '.join(sorted(VALID_BYPASS_METHODS)))
    sys.exit(1)
FAKE_TTL = config.get("FAKE_TTL", 1)              # TTL for low_ttl method (hops before expiry)
SEGMENT_SIZE = config.get("SEGMENT_SIZE", 2)       # Bytes per segment for tcp_segmentation
SEGMENT_DELAY = config.get("SEGMENT_DELAY", 0.001) # Seconds between segments for tcp_segmentation
IP_FRAG_OFFSET = config.get("IP_FRAG_OFFSET", 8)  # Bytes in first IP fragment for ip_fragmentation (must be multiple of 8)
TLS_RECORD_FRAG_SIZE = config.get("TLS_RECORD_FRAG_SIZE", 5) # Bytes per TLS record fragment for tls_record_frag
URGENT_POINTER_SIZE = config.get("URGENT_POINTER_SIZE", 3)    # Bytes of urgent data prefix for tcp_urgent_pointer

# Connection & timing configuration
BYPASS_TIMEOUT = config.get("BYPASS_TIMEOUT", 2)              # Seconds to wait for bypass confirmation
CLIENT_DATA_TIMEOUT = config.get("CLIENT_DATA_TIMEOUT", 5)    # Seconds to wait for client's first data
FAKE_INJECT_DELAY = config.get("FAKE_INJECT_DELAY", 0.001)    # Seconds to delay before injecting fake packet

# TCP keep-alive configuration
KEEPALIVE_IDLE = config.get("KEEPALIVE_IDLE", 11)             # Seconds idle before first keep-alive probe
KEEPALIVE_INTERVAL = config.get("KEEPALIVE_INTERVAL", 2)      # Seconds between keep-alive probes
KEEPALIVE_COUNT = config.get("KEEPALIVE_COUNT", 3)            # Max keep-alive probes before dropping
METRICS_INTERVAL = config.get("METRICS_INTERVAL", 10)         # Seconds between dashboard prints (0 = disabled)
MAX_CONNECTIONS = config.get("MAX_CONNECTIONS", 100)           # Max simultaneous connections (0 = unlimited)
SHOW_FAILED_SNIS = config.get("SHOW_FAILED_SNIS", True)       # Show unreachable SNIs in the selection list
SCAN_WORKERS = config.get("SCAN_WORKERS", 20)                  # Concurrent threads for SNI scanning
SCAN_TIMEOUT = config.get("SCAN_TIMEOUT", 2.0)                 # Per-SNI scan timeout (seconds)
SCAN_TLS_PROBE = config.get("SCAN_TLS_PROBE", True)            # Verify TLS handshake (not just TCP)
SCAN_TTL_PROBE = config.get("SCAN_TTL_PROBE", True)            # Estimate hop count via ping
SCAN_CACHE_TTL = config.get("SCAN_CACHE_TTL", 300)             # Seconds to reuse cached scan results (0 = disabled)
SCAN_DEGRADED_RETRIES = config.get("SCAN_DEGRADED_RETRIES", 2) # Extra attempts for timeout-degraded SNIs (0 = disabled)
SCAN_DEGRADED_TIMEOUT = config.get("SCAN_DEGRADED_TIMEOUT", 5.0) # Timeout (seconds) for degraded-SNI retry attempts
AUTO_SELECT_SNI = config.get("AUTO_SELECT_SNI", False)          # Auto-pick best SNI without prompt
AUTO_SELECT_INTERVAL = config.get("AUTO_SELECT_INTERVAL", 5)    # Minutes between background SNI re-scans (0 = disabled)
LOG_TO_FILE = config.get("LOG_TO_FILE", False)                  # Write a per-run log file to logs/ (false = disabled)

# Performance tuning
RELAY_BUFFER_SIZE = config.get("RELAY_BUFFER_SIZE", 262144)     # Read buffer size per relay direction (bytes)
SOCKET_BUFFER_SIZE = config.get("SOCKET_BUFFER_SIZE", 262144)   # OS socket send/recv buffer size (bytes)
INJECTION_POOL_SIZE = config.get("INJECTION_POOL_SIZE", 32)     # Injection thread pool workers

# ----- Configuration Validation -----
if SEGMENT_SIZE < 1:
    logger.critical("SEGMENT_SIZE must be >= 1")
    sys.exit(1)
if TLS_RECORD_FRAG_SIZE < 1:
    logger.critical("TLS_RECORD_FRAG_SIZE must be >= 1")
    sys.exit(1)
if FAKE_TTL < 1 or FAKE_TTL > 255:
    logger.critical("FAKE_TTL must be between 1 and 255")
    sys.exit(1)
if URGENT_POINTER_SIZE < 1:
    logger.critical("URGENT_POINTER_SIZE must be >= 1")
    sys.exit(1)
if IP_FRAG_OFFSET < 8 or IP_FRAG_OFFSET % 8 != 0:
    logger.critical("IP_FRAG_OFFSET must be a positive multiple of 8")
    sys.exit(1)
if AUTO_SELECT_INTERVAL < 0:
    logger.critical("AUTO_SELECT_INTERVAL must be >= 0")
    sys.exit(1)
if not (4096 <= RELAY_BUFFER_SIZE <= 1048576):
    logger.critical("RELAY_BUFFER_SIZE must be between 4096 and 1048576")
    sys.exit(1)
if not (4096 <= SOCKET_BUFFER_SIZE <= 4194304):
    logger.critical("SOCKET_BUFFER_SIZE must be between 4096 and 4194304")
    sys.exit(1)
if not (1 <= INJECTION_POOL_SIZE <= 256):
    logger.critical("INJECTION_POOL_SIZE must be between 1 and 256")
    sys.exit(1)

# ----- CDN Range Lookup -----

def load_cdn_ranges() -> dict[str, list[ipaddress.IPv4Network]]:
    """Load CDN IP ranges from cdn_ranges.json."""
    path = os.path.join(get_exe_dir(), 'cdn_ranges.json')
    if not os.path.isfile(path):
        return {}
    with open(path, 'r', encoding='utf-8') as f:
        raw: dict[str, list[str]] = json.load(f)
    return {
        name: [ipaddress.IPv4Network(cidr, strict=False) for cidr in cidrs]
        for name, cidrs in raw.items()
    }


CDN_RANGES: dict[str, list[ipaddress.IPv4Network]] = load_cdn_ranges()


def get_cdn_label(ip: str) -> str:
    """Return the CDN name that owns the given IP, or 'Unknown'."""
    try:
        addr = ipaddress.IPv4Address(ip)
    except ValueError:
        return "Unknown"
    for name, networks in CDN_RANGES.items():
        for network in networks:
            if addr in network:
                return name
    return "Unknown"


# ----- SNI List Loading & Selection -----

@dataclasses.dataclass
class SniResult:
    sni: str
    ip: str | None
    tcp_ok: bool
    tls_ok: bool | None       # None = probe disabled or TCP failed
    latency_ms: float | None   # TCP connect latency
    ttl_hops: int | None       # estimated hops from ping reply TTL
    cdn: str
    tcp_fail_reason: str | None = None  # "timeout", "refused", "error", or None when tcp_ok

    def sort_key(self) -> tuple:
        """Lower is better: (status_bucket, latency)."""
        if self.tls_ok:
            bucket = 0
        elif self.tcp_ok:
            bucket = 1
        elif self.ip is not None and self.tcp_fail_reason in ("timeout", None):
            # Timeout-degraded: may still work through the proxy
            bucket = 2
        elif self.ip is not None:
            # Refused or hard error: unlikely to work
            bucket = 3
        else:
            bucket = 4
        lat = self.latency_ms if self.latency_ms is not None else float('inf')
        return (bucket, lat)

    def to_cache_dict(self) -> dict:
        return {
            "ip": self.ip,
            "tcp_ok": self.tcp_ok,
            "tls_ok": self.tls_ok,
            "latency_ms": self.latency_ms,
            "ttl_hops": self.ttl_hops,
            "cdn": self.cdn,
            "tcp_fail_reason": self.tcp_fail_reason,
            "timestamp": time.time(),
        }

    @classmethod
    def from_cache(cls, sni: str, d: dict) -> "SniResult":
        return cls(
            sni=sni,
            ip=d.get("ip"),
            tcp_ok=d.get("tcp_ok", False),
            tls_ok=d.get("tls_ok"),
            latency_ms=d.get("latency_ms"),
            ttl_hops=d.get("ttl_hops"),
            cdn=d.get("cdn", "Unknown"),
            tcp_fail_reason=d.get("tcp_fail_reason"),
        )


def _scan_cache_path() -> str:
    return os.path.join(get_exe_dir(), 'sni_scan_cache.json')


def _load_scan_cache() -> dict[str, dict]:
    path = _scan_cache_path()
    if not os.path.isfile(path):
        return {}
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save_scan_cache(results: list[SniResult]):
    cache: dict[str, dict] = {}
    for r in results:
        cache[r.sni] = r.to_cache_dict()
    target = _scan_cache_path()
    tmp = target + ".tmp"
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(cache, f, indent=2)
        os.replace(tmp, target)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def load_snis() -> list[str]:
    """Load SNI domains from sni_list.txt (one per line, # comments, blank lines ignored).
    Removes duplicate entries and saves the cleaned list back to the file."""
    sni_path = os.path.join(get_exe_dir(), 'sni_list.txt')
    if not os.path.isfile(sni_path):
        return []
    comment_lines = []
    snis = []
    seen = set()
    duplicates = 0
    with open(sni_path, 'r', encoding='utf-8') as f:
        for line in f:
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                comment_lines.append(line.rstrip('\n'))
            else:
                lower = stripped.lower()
                if lower in seen:
                    duplicates += 1
                else:
                    seen.add(lower)
                    snis.append(stripped)
    if duplicates:
        logger.info("Removed %d duplicate SNI(s) from sni_list.txt", duplicates)
        with open(sni_path, 'w', encoding='utf-8') as f:
            for cl in comment_lines:
                f.write(cl + '\n')
            for sni in snis:
                f.write(sni + '\n')
    return snis


def _estimate_hops(ttl: int) -> int:
    """Estimate hop count from a ping reply TTL value."""
    if ttl <= 64:
        return 64 - ttl
    if ttl <= 128:
        return 128 - ttl
    return 255 - ttl


def check_sni(sni: str, port: int = 443, timeout: float = 2.0) -> SniResult:
    """
    Check a single SNI: resolve DNS, TCP connect (with latency), optional TLS
    handshake probe, and optional TTL/hop estimation via ping.
    """
    # 1. DNS resolve
    try:
        ip = socket.gethostbyname(sni)
    except socket.gaierror:
        return SniResult(sni=sni, ip=None, tcp_ok=False, tls_ok=None,
                         latency_ms=None, ttl_hops=None, cdn="Unknown")

    cdn = get_cdn_label(ip)

    # 2. TCP connect with timing
    latency_ms = None
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.settimeout(timeout)
        t0 = time.perf_counter()
        s.connect((ip, port))
        latency_ms = (time.perf_counter() - t0) * 1000
    except ConnectionRefusedError:
        return SniResult(sni=sni, ip=ip, tcp_ok=False, tls_ok=None,
                         latency_ms=None, ttl_hops=None, cdn=cdn, tcp_fail_reason="refused")
    except (socket.timeout, TimeoutError):
        return SniResult(sni=sni, ip=ip, tcp_ok=False, tls_ok=None,
                         latency_ms=None, ttl_hops=None, cdn=cdn, tcp_fail_reason="timeout")
    except OSError:
        return SniResult(sni=sni, ip=ip, tcp_ok=False, tls_ok=None,
                         latency_ms=None, ttl_hops=None, cdn=cdn, tcp_fail_reason="error")
    finally:
        s.close()

    # 3. TLS handshake probe (fresh socket)
    tls_ok = None
    if SCAN_TLS_PROBE:
        tls_ok = False
        s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s2.settimeout(timeout)
            s2.connect((ip, port))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(s2, server_hostname=sni) as tls_sock:
                tls_ok = True
        except Exception:
            pass
        finally:
            s2.close()

    # 4. TTL/hop estimation via ping
    ttl_hops = None
    if SCAN_TTL_PROBE:
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '500', ip],
                capture_output=True, text=True, timeout=3,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            m = re.search(r'TTL[=:](\d+)', result.stdout, re.IGNORECASE)
            if m:
                ttl_hops = _estimate_hops(int(m.group(1)))
        except (subprocess.TimeoutExpired, OSError):
            pass

    return SniResult(sni=sni, ip=ip, tcp_ok=True, tls_ok=tls_ok,
                     latency_ms=latency_ms, ttl_hops=ttl_hops, cdn=cdn)


def suggest_bypass(cdn: str, ttl_hops: int | None) -> str:
    """Suggest a bypass method based on CDN provider and hop count."""
    if ttl_hops is not None and 1 <= ttl_hops <= 15:
        ttl_val = max(1, ttl_hops - 1)
        return f"low_ttl (FAKE_TTL={ttl_val})"
    if cdn in {"Cloudflare", "Fastly", "Akamai"}:
        return "wrong_checksum"
    return "wrong_seq"


def _format_sni_row(num: int, r: SniResult) -> tuple[str, tuple]:
    """Format a single SNI result row for display — returns (row_style, cells)."""
    if r.tcp_ok:
        if r.tls_ok:
            status = Text("✓ TLS", style="bold green")
            row_style = "green"
        else:
            status = Text("⚠ TCP", style="bold yellow")
            row_style = "yellow"
        ip_str = r.ip or ""
        lat_str = f"{r.latency_ms:.0f} ms" if r.latency_ms is not None else "N/A"
        tls_str = Text("✓", style="bold green") if r.tls_ok else (
            Text("✗", style="bold red") if r.tls_ok is False else Text("—", style="dim")
        )
        hops_str = f"~{r.ttl_hops}" if r.ttl_hops is not None else "—"
        suggestion = suggest_bypass(r.cdn, r.ttl_hops)
    elif r.ip is not None:
        if r.tcp_fail_reason == "refused":
            status = Text("✗ Refused", style="red")
            row_style = ""
            suggestion = "—"
        elif r.tcp_fail_reason == "error":
            status = Text("✗ TCP fail", style="red")
            row_style = ""
            suggestion = "—"
        else:  # "timeout" or legacy None — potentially usable through proxy
            status = Text("⚠ Degraded", style="bold yellow")
            row_style = "dim"
            suggestion = suggest_bypass(r.cdn, None)
        ip_str = r.ip
        lat_str = "—"
        tls_str = Text("—", style="dim")
        hops_str = "—"
    else:
        status = Text("✗ DNS fail", style="bold red")
        row_style = ""
        ip_str = "—"
        lat_str = "—"
        tls_str = Text("—", style="dim")
        hops_str = "—"
        suggestion = "—"
    return row_style, (str(num), status, r.sni, ip_str, r.cdn, lat_str, tls_str, hops_str, suggestion)


def _format_scan_line(r: SniResult, prefix: str = "") -> str:
    """Return a compact Rich markup string for one SNI probe result."""
    if r.ip is None:
        # DNS failure
        return f"{prefix}[bold red]✗ DNS fail[/bold red]  [bold]{r.sni}[/bold]"

    ip_part = f" [dim]({r.ip})[/dim]"

    if r.tcp_ok:
        lat_part = f"  [dim]{r.latency_ms:.0f} ms[/dim]" if r.latency_ms is not None else ""
        cdn_part = f"  [dim]{r.cdn}[/dim]" if r.cdn and r.cdn not in ("Unknown", "") else ""
        if r.tls_ok:
            status = "[bold green]✓ TLS[/bold green]"
        else:
            status = "[bold yellow]⚠ TCP[/bold yellow]"
        return f"{prefix}{status}  [bold]{r.sni}[/bold]{ip_part}{lat_part}{cdn_part}"

    # TCP failed
    cdn_part = f"  [dim]{r.cdn}[/dim]" if r.cdn and r.cdn not in ("Unknown", "") else ""
    if r.tcp_fail_reason == "timeout":
        return f"{prefix}[yellow dim]⚠ Timeout[/yellow dim]  [dim]{r.sni}[/dim]{ip_part}{cdn_part}"
    elif r.tcp_fail_reason == "refused":
        return f"{prefix}[red]✗ Refused[/red]  [dim]{r.sni}[/dim]{ip_part}{cdn_part}"
    else:
        return f"{prefix}[red]✗ Error[/red]  [dim]{r.sni}[/dim]{ip_part}{cdn_part}"


def _run_scan(snis: list[str], use_cache: bool, show_progress: bool = True) -> list[SniResult]:
    """
    Scan a list of SNI domains, returning a SniResult for each.
    Results are cached to sni_scan_cache.json when SCAN_CACHE_TTL > 0.

    Args:
        snis:          List of domain names to scan.
        use_cache:     If True, reuse unexpired cached results.
        show_progress: If True, print a live scanning progress line to stdout.
                       Pass False for background/silent scans.
    """
    cache = _load_scan_cache() if use_cache and SCAN_CACHE_TTL > 0 else {}
    now = time.time()
    results: list[SniResult] = [None] * len(snis)  # type: ignore[list-item]
    to_scan: list[int] = []  # indices that need fresh scanning

    # Populate from cache where valid
    for i, sni in enumerate(snis):
        entry = cache.get(sni)
        if entry and SCAN_CACHE_TTL > 0 and now - entry.get("timestamp", 0) < SCAN_CACHE_TTL:
            results[i] = SniResult.from_cache(sni, entry)
        else:
            to_scan.append(i)

    cached_count = len(snis) - len(to_scan)
    total = len(snis)
    if show_progress and cached_count:
        console.print(f"  [cyan]Using cached results for {cached_count}/{total} SNI(s)[/cyan]")

    if to_scan:
        workers = min(len(to_scan), SCAN_WORKERS)
        if show_progress:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=console,
                transient=False,
            )
            task_id = progress.add_task("[cyan]Scanning SNIs...", total=len(to_scan))
            with progress:
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    future_to_idx = {
                        pool.submit(check_sni, snis[i], CONNECT_PORT, SCAN_TIMEOUT): i
                        for i in to_scan
                    }
                    for future in concurrent.futures.as_completed(future_to_idx):
                        idx = future_to_idx[future]
                        results[idx] = future.result()
                        progress.console.print(_format_scan_line(results[idx]))
                        progress.advance(task_id)
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                future_to_idx = {
                    pool.submit(check_sni, snis[i], CONNECT_PORT, SCAN_TIMEOUT): i
                    for i in to_scan
                }
                for future in concurrent.futures.as_completed(future_to_idx):
                    idx = future_to_idx[future]
                    results[idx] = future.result()

    # Retry pass: re-probe timeout-degraded SNIs with a longer timeout and reduced
    # parallelism. A SNI that timed out under the fast parallel scan might simply be
    # slow or have been rate-limited; a successful retry promotes it to tcp_ok=True.
    # A retry that comes back as "refused" downgrades it from "degraded" to "refused".
    if SCAN_DEGRADED_RETRIES > 0:
        degraded_idxs = [
            i for i, r in enumerate(results)
            if r is not None and not r.tcp_ok
            and r.ip is not None and r.tcp_fail_reason == "timeout"
        ]
        if degraded_idxs:
            if show_progress:
                console.print(
                    f"  [yellow]Retrying {len(degraded_idxs)} timeout-degraded SNI(s) "
                    f"(up to {SCAN_DEGRADED_RETRIES}\u00d7, {SCAN_DEGRADED_TIMEOUT:.1f}s timeout)...[/yellow]"
                )

            def _retry_one(idx: int) -> tuple[int, SniResult]:
                original = results[idx]
                for _ in range(SCAN_DEGRADED_RETRIES):
                    r = check_sni(original.sni, port=CONNECT_PORT, timeout=SCAN_DEGRADED_TIMEOUT)
                    if r.tcp_ok or r.tcp_fail_reason != "timeout":
                        return idx, r
                return idx, original  # still timing out — keep as degraded

            retry_workers = max(1, min(len(degraded_idxs), SCAN_WORKERS // 2))
            if show_progress:
                retry_progress = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TimeElapsedColumn(),
                    console=console,
                    transient=False,
                )
                retry_task = retry_progress.add_task(
                    "[yellow]Retrying degraded SNIs...", total=len(degraded_idxs)
                )
                with retry_progress:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=retry_workers) as pool:
                        futures = {pool.submit(_retry_one, i): i for i in degraded_idxs}
                        for future in concurrent.futures.as_completed(futures):
                            idx, updated = future.result()
                            results[idx] = updated
                            retry_progress.console.print(_format_scan_line(updated, prefix="↻ "))
                            retry_progress.advance(retry_task)
            else:
                with concurrent.futures.ThreadPoolExecutor(max_workers=retry_workers) as pool:
                    futures = {pool.submit(_retry_one, i): i for i in degraded_idxs}
                    for future in concurrent.futures.as_completed(futures):
                        idx, updated = future.result()
                        results[idx] = updated

    # Persist all results to cache
    _save_scan_cache([r for r in results if r is not None])
    return results


def _pick_best_result(results: list[SniResult]) -> SniResult | None:
    """Return the best reachable SNI result (lowest sort_key() among tcp_ok with valid IP)."""
    reachable = [r for r in results if r.tcp_ok and r.ip is not None]
    if not reachable:
        return None
    return min(reachable, key=lambda r: r.sort_key())


def select_sni_interactive():
    """
    Load sni_list.txt, check all SNIs, display sorted results with rich info,
    let user pick one (or auto-select).
    Updates global FAKE_SNI_STR, FAKE_SNI, CONNECT_IP, INTERFACE_IPV4.
    Exits if sni_list.txt is missing/empty or no valid SNI can be selected.
    """
    global FAKE_SNI_STR, FAKE_SNI, CONNECT_IP, INTERFACE_IPV4

    snis = load_snis()
    if not snis:
        logger.critical("No SNI domains found. Add at least one domain to sni_list.txt.")
        sys.exit(1)

    console.rule("[bold cyan]SNI Scanner[/bold cyan]")
    results = _run_scan(snis, use_cache=True)
    _log_scan_results(results, "Initial SNI Scan")

    def _display_results(results: list[SniResult]) -> list[SniResult]:
        """Sort, display, and return the display-ordered list."""
        sorted_results = sorted(results, key=lambda r: r.sort_key())

        # Determine which results to include in display.
        # - Always show: tcp_ok (all quality levels)
        # - Always show: timeout-degraded (TCP timed out but may work through proxy)
        # - Only with SHOW_FAILED_SNIS: refused/error TCP fails and DNS fails
        display_list: list[SniResult] = []
        for r in sorted_results:
            if r.tcp_ok:
                display_list.append(r)
            elif r.ip is not None and r.tcp_fail_reason in ("timeout", None):
                display_list.append(r)
            elif SHOW_FAILED_SNIS:
                display_list.append(r)

        table = Table(
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
            show_lines=False,
            expand=False,
            padding=(0, 1),
        )
        table.add_column("#",          style="dim", width=3, justify="right")
        table.add_column("Status",     width=10)
        table.add_column("Domain",     style="bold", min_width=20)
        table.add_column("IP",         min_width=13)
        table.add_column("CDN",        min_width=10)
        table.add_column("Latency",    min_width=8, justify="right")
        table.add_column("TLS",        width=4,  justify="center")
        table.add_column("Hops",       width=6,  justify="center")
        table.add_column("Suggested Method", style="cyan", min_width=16)

        for i, r in enumerate(display_list, 1):
            row_style, cells = _format_sni_row(i, r)
            table.add_row(*cells, style=row_style)

        console.print(table)

        # Summary line
        reachable = sum(1 for r in results if r.tcp_ok)
        tls_verified = sum(1 for r in results if r.tls_ok)
        degraded = sum(1 for r in results if not r.tcp_ok and r.ip is not None
                       and r.tcp_fail_reason in ("timeout", None))
        refused = sum(1 for r in results if not r.tcp_ok and r.ip is not None
                      and r.tcp_fail_reason not in ("timeout", None))
        total = len(results)
        summary = (
            f"  [cyan]Reachable:[/cyan] [bold]{reachable}/{total}[/bold]   "
            f"[cyan]TLS verified:[/cyan] [bold]{tls_verified}/{total}[/bold]"
        )
        if degraded:
            summary += f"   [cyan]Degraded (timeout, may work):[/cyan] [bold yellow]{degraded}[/bold yellow]"
        if refused:
            summary += f"   [cyan]Refused:[/cyan] [bold red]{refused}[/bold red]"
        console.print(summary)
        console.print()
        return display_list

    display_list = _display_results(results)

    # Auto-select mode
    if AUTO_SELECT_SNI:
        best = _pick_best_result(results)
        if best is None:
            logger.critical("AUTO_SELECT_SNI is enabled but no reachable SNI found.")
            sys.exit(1)
        FAKE_SNI_STR = best.sni
        FAKE_SNI = best.sni.encode()
        CONNECT_IP = best.ip
        INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
        console.print(f"  [bold green]Auto-selected:[/bold green] {best.sni} [dim]→[/dim] {best.ip}")
        if _log_file is not None:
            _log_file.write(f"[Selected] {best.sni} -> {best.ip}\n")
            _log_file.flush()
        return

    # Interactive prompt with rescan support
    while True:
        # Flush any keystrokes buffered during the scan so they don't pollute
        # the selection prompt (e.g. keys typed while watching the progress bar).
        try:
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getwch()
        except Exception:
            pass
        try:
            choice = input("  Select SNI number (or 'r' to rescan): ").strip().lower()
        except EOFError:
            console.print("  [yellow]Invalid input. Enter a number or 'r'.[/yellow]")
            continue

        if choice in ('r', 'rescan'):
            # Delete cache and re-scan
            try:
                os.remove(_scan_cache_path())
            except OSError:
                pass
            console.rule("[bold cyan]Rescanning[/bold cyan]")
            results = _run_scan(snis, use_cache=False)
            _log_scan_results(results, "SNI Rescan")
            display_list = _display_results(results)
            continue

        try:
            num = int(choice)
        except ValueError:
            console.print("  [yellow]Invalid input. Enter a number or 'r'.[/yellow]")
            continue

        if 1 <= num <= len(display_list):
            r = display_list[num - 1]
            if not r.tcp_ok:
                console.print(f"  [yellow]Warning:[/yellow] {r.sni} failed connectivity check. Selecting anyway.")
            if r.ip is None:
                console.print(f"  [red]Error:[/red] DNS resolution failed for {r.sni}. Cannot use this SNI.")
                continue
            FAKE_SNI_STR = r.sni
            FAKE_SNI = r.sni.encode()
            CONNECT_IP = r.ip
            INTERFACE_IPV4 = get_default_interface_ipv4(CONNECT_IP)
            console.print(f"  [bold green]Selected:[/bold green] {r.sni} [dim]→[/dim] {r.ip}")
            if _log_file is not None:
                _log_file.write(f"[Selected] {r.sni} -> {r.ip}\n")
                _log_file.flush()
            return
        console.print(f"  [yellow]Enter a number between 1 and {len(display_list)}.[/yellow]")


# ----- Global State -----
# Registry of active connections being monitored for packet injection.
# Keyed by (src_ip, src_port, dst_ip, dst_port) tuple.
_connections_lock = threading.Lock()
fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}

# Lock protecting FAKE_SNI / CONNECT_IP / INTERFACE_IPV4 updates from the
# background SNI refresh thread.
_sni_lock = threading.Lock()

# Reference to the active WinDivert injector; replaced on each SNI/IP switch.
fake_tcp_injector: FakeTcpInjector | None = None

# Connection limiter (None = unlimited)
_conn_semaphore: asyncio.Semaphore | None = asyncio.Semaphore(MAX_CONNECTIONS) if MAX_CONNECTIONS > 0 else None


def _build_w_filter() -> str:
    """Build a WinDivert TCP filter for traffic between our interface and the target server."""
    with _sni_lock:
        _iface = INTERFACE_IPV4
        _cip = CONNECT_IP
    return (
        "tcp and ("
        f"(ip.SrcAddr == {_iface} and ip.DstAddr == {_cip})"
        " or "
        f"(ip.SrcAddr == {_cip} and ip.DstAddr == {_iface})"
        ")"
    )


def _restart_injector():
    """Stop the current WinDivert injector (if any) and start a new one with the current filter."""
    global fake_tcp_injector
    if fake_tcp_injector is not None:
        fake_tcp_injector.stop()
    new_injector = FakeTcpInjector(_build_w_filter(), fake_injective_connections, _connections_lock,
                                   INJECTION_POOL_SIZE)
    fake_tcp_injector = new_injector
    threading.Thread(target=new_injector.run, args=(), daemon=True).start()


def _background_sni_refresh():
    """
    Background daemon thread: periodically re-scans SNIs and updates the active
    SNI/IP without interrupting existing connections.

    - Runs every AUTO_SELECT_INTERVAL minutes.
    - Always performs a fresh scan (bypasses cache).
    - If the best SNI changed OR its resolved IP changed, updates the module
      globals and restarts the WinDivert injector with the new filter.
    - Existing in-flight connections are unaffected (they use local snapshots
      captured at connection start inside handle()).
    """
    global FAKE_SNI_STR, FAKE_SNI, CONNECT_IP, INTERFACE_IPV4

    cycle = 0
    while True:
        global _next_sni_refresh_time
        _next_sni_refresh_time = time.monotonic() + AUTO_SELECT_INTERVAL * 60
        time.sleep(AUTO_SELECT_INTERVAL * 60)
        _next_sni_refresh_time = None
        cycle += 1
        try:
            snis = load_snis()
            if not snis:
                logger.warning("[SNI refresh] sni_list.txt is empty — skipping refresh.")
                continue

            results = _run_scan(snis, use_cache=False, show_progress=False)
            _log_scan_results(results, f"Background Refresh #{cycle}")
            best = _pick_best_result(results)

            if best is None:
                logger.warning("[SNI refresh] No reachable SNI found during background scan.")
                if _log_file is not None:
                    _log_file.write(f"[No reachable SNI] Background Refresh #{cycle} — no valid SNI found\n")
                    _log_file.flush()
                continue

            with _sni_lock:
                old_sni = FAKE_SNI_STR
                old_ip = CONNECT_IP

                sni_changed = best.sni != old_sni
                ip_changed = best.ip != old_ip

                if sni_changed or ip_changed:
                    FAKE_SNI_STR = best.sni
                    FAKE_SNI = best.sni.encode()
                    CONNECT_IP = best.ip
                    INTERFACE_IPV4 = get_default_interface_ipv4(best.ip)

            if sni_changed or ip_changed:
                # Build detail string for the new SNI
                lat_part = f"  [dim]latency {best.latency_ms:.0f} ms[/dim]" if best.latency_ms is not None else ""
                tls_part = (
                    "  [bold green]TLS ✓[/bold green]" if best.tls_ok
                    else ("  [bold yellow]TCP only[/bold yellow]" if best.tcp_ok else "  [bold red]unreachable[/bold red]")
                )
                cdn_part = f"  [dim]{best.cdn}[/dim]" if best.cdn not in ("Unknown", "") else ""
                hops_part = f"  [dim]~{best.ttl_hops} hops[/dim]" if best.ttl_hops is not None else ""

            if sni_changed:
                console.print(
                    f"  [bold magenta]\\[SNI refresh][/bold magenta] "
                    f"Switched SNI: [yellow]{old_sni}[/yellow] [dim]→[/dim] "
                    f"[green]{best.sni}[/green] [dim]({best.ip})[/dim]"
                    f"{tls_part}{lat_part}{hops_part}{cdn_part}"
                )
                if _log_file is not None:
                    _log_file.write(f"[Selected] {best.sni} -> {best.ip}  (switched from {old_sni})\n")
                    _log_file.flush()
                _restart_injector()
            elif ip_changed:
                console.print(
                    f"  [bold magenta]\\[SNI refresh][/bold magenta] "
                    f"IP updated for [green]{best.sni}[/green]: "
                    f"[yellow]{old_ip}[/yellow] [dim]→[/dim] [green]{best.ip}[/green]"
                    f"{tls_part}{lat_part}{hops_part}{cdn_part}"
                )
                if _log_file is not None:
                    _log_file.write(f"[Selected] {best.sni} -> {best.ip}  (IP changed from {old_ip})\n")
                    _log_file.flush()
                _restart_injector()
            else:
                logger.debug("[SNI refresh] No change — still using %s -> %s", best.sni, best.ip)
                if _log_file is not None:
                    _log_file.write(f"[No change] {best.sni} -> {best.ip}\n")
                    _log_file.flush()

        except Exception:
            logger.exception("[SNI refresh] Unexpected error during background SNI refresh.")
        finally:
            _next_sni_refresh_time = None


async def _one_way_relay(sock_in: socket.socket, sock_out: socket.socket):
    """Relay data from sock_in to sock_out until EOF or error."""
    loop = asyncio.get_running_loop()
    try:
        while True:
            data = await loop.sock_recv(sock_in, RELAY_BUFFER_SIZE)
            if not data:
                # Clean close — peer sent FIN
                return
            await loop.sock_sendall(sock_out, data)
            metrics.bytes_transferred(len(data))
    except ConnectionResetError:
        logger.debug("Connection reset by peer (%s -> %s)",
                     sock_in.getpeername() if sock_in.fileno() != -1 else "?",
                     sock_out.getpeername() if sock_out.fileno() != -1 else "?")
        metrics.relay_broken()
        raise
    except OSError as exc:
        logger.debug("Connection broken: %s", exc)
        metrics.relay_broken()
        raise


async def relay_bidirectional(sock_a: socket.socket, sock_b: socket.socket):
    """Relay data bidirectionally between two sockets until either side closes."""
    task_a2b = asyncio.create_task(_one_way_relay(sock_a, sock_b))
    task_b2a = asyncio.create_task(_one_way_relay(sock_b, sock_a))
    done, pending = await asyncio.wait(
        [task_a2b, task_b2a], return_when=asyncio.FIRST_COMPLETED)
    for t in done:
        try:
            t.result()
        except Exception:
            pass
    # Close both sockets before waiting for the pending task to finish.
    # On Windows, IOCP WSARecv/WSASend cancellation (CancelIoEx) is
    # asynchronous and can take an arbitrarily long time to deliver the
    # abort completion.  Closing the sockets immediately forces any
    # pending operation to complete with an error, so `await t` returns
    # in microseconds instead of potentially hanging forever.
    for s in (sock_a, sock_b):
        try:
            s.close()
        except OSError:
            pass
    for t in pending:
        t.cancel()
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    """
    Handles a single proxied connection:
    1. Generates a fake TLS ClientHello with the spoofed SNI and random fields.
    2. Opens an outgoing TCP socket to the target server.
    3. Registers a FakeInjectiveConnection so the packet injector can intercept
       the TCP handshake and inject the fake ClientHello with a wrong sequence number.
    4. Waits for the injector to confirm DPI bypass success.
    5. Starts bidirectional relay between the incoming client and the outgoing server.
    """
    if _conn_semaphore is not None:
        await _conn_semaphore.acquire()
    metrics.connection_started()
    outgoing_sock = None
    try:
        # Snapshot SNI/IP globals under the lock so a concurrent background refresh
        # cannot change them mid-connection.
        with _sni_lock:
            _fake_sni: bytes = FAKE_SNI
            _connect_ip: str = CONNECT_IP
            _interface_ipv4: str = INTERFACE_IPV4

        loop = asyncio.get_running_loop()
        if DATA_MODE == "tls":
                # Build a fake TLS ClientHello with random values and the spoofed SNI
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), _fake_sni,
                                                               os.urandom(32))
        else:
            logger.error("Unsupported DATA_MODE: %s", DATA_MODE)
            incoming_sock.close()
            return
        # Create outgoing socket to the target server with TCP keep-alive settings
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((_interface_ipv4, 0))  # Bind to detected interface, OS assigns port
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
        src_port = outgoing_sock.getsockname()[1]  # Get the OS-assigned ephemeral port

        if BYPASS_METHOD == "tcp_segmentation":
            # --- TCP Segmentation bypass ---
            # No fake packet injection needed. Connect normally, then split the first
            # data chunk (the real ClientHello from the client) into tiny TCP segments
            # so DPI cannot reassemble the SNI from a single packet.
            try:
                await loop.sock_connect(outgoing_sock, (_connect_ip, CONNECT_PORT))
            except Exception:
                metrics.connect_failed()
                outgoing_sock.close()
                incoming_sock.close()
                return

            # Enable TCP_NODELAY to force each small write into its own TCP segment
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Read the first data chunk from the client (the real TLS ClientHello)
            try:
                first_data = await asyncio.wait_for(loop.sock_recv(incoming_sock, 65575), CLIENT_DATA_TIMEOUT)
                if not first_data:
                    raise ValueError("no data from client")
            except Exception:
                outgoing_sock.close()
                incoming_sock.close()
                return

            # Send the ClientHello in small segments to split the SNI across packets
            try:
                for i in range(0, len(first_data), SEGMENT_SIZE):
                    segment = first_data[i:i + SEGMENT_SIZE]
                    await loop.sock_sendall(outgoing_sock, segment)
                    if i + SEGMENT_SIZE < len(first_data):
                        await asyncio.sleep(SEGMENT_DELAY)
            except Exception:
                outgoing_sock.close()
                incoming_sock.close()
                return

            # Disable TCP_NODELAY for normal relay performance
            outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
            metrics.bypass_succeeded()

        elif BYPASS_METHOD == "tls_record_frag":
            # --- TLS Record Fragmentation bypass ---
            # Split the real ClientHello into multiple TLS record fragments.
            # Each fragment is a valid TLS record but contains only a few bytes of
            # the handshake message, so DPI can't extract the SNI from any single record.
            try:
                await loop.sock_connect(outgoing_sock, (_connect_ip, CONNECT_PORT))
            except Exception:
                metrics.connect_failed()
                outgoing_sock.close()
                incoming_sock.close()
                return

            # Read the first data chunk from the client (the real TLS ClientHello)
            try:
                first_data = await asyncio.wait_for(loop.sock_recv(incoming_sock, 65575), CLIENT_DATA_TIMEOUT)
                if not first_data:
                    raise ValueError("no data from client")
            except Exception:
                outgoing_sock.close()
                incoming_sock.close()
                return

            # The first_data should be a TLS record: 1 byte type + 2 bytes version + 2 bytes length + payload
            # We re-wrap the handshake payload into multiple small TLS records
            try:
                if len(first_data) >= 5 and first_data[0] == 0x16:  # TLS Handshake record
                    tls_type = first_data[0:1]        # 0x16 = Handshake
                    tls_version = first_data[1:3]     # e.g. 0x0301 = TLS 1.0
                    handshake_payload = first_data[5:]  # Skip the 5-byte TLS record header

                    # Enable TCP_NODELAY to force each record into its own segment
                    outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                    # Split handshake payload into small TLS records
                    for i in range(0, len(handshake_payload), TLS_RECORD_FRAG_SIZE):
                        chunk = handshake_payload[i:i + TLS_RECORD_FRAG_SIZE]
                        # Build a TLS record: type(1) + version(2) + length(2) + chunk
                        record = tls_type + tls_version + struct.pack("!H", len(chunk)) + chunk
                        await loop.sock_sendall(outgoing_sock, record)
                        if i + TLS_RECORD_FRAG_SIZE < len(handshake_payload):
                            await asyncio.sleep(SEGMENT_DELAY)

                    outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
                else:
                    # Not a TLS handshake record — send as-is
                    await loop.sock_sendall(outgoing_sock, first_data)
            except Exception:
                outgoing_sock.close()
                incoming_sock.close()
                return
            metrics.bypass_succeeded()

        else:
            # --- Injection-based bypass methods (wrong_seq, wrong_checksum, low_ttl, duplicate_syn) ---
            # Register this connection for packet-level monitoring and injection
            fake_injective_conn = FakeInjectiveConnection(outgoing_sock, _interface_ipv4, _connect_ip, src_port, CONNECT_PORT,
                                                          fake_data,
                                                          BYPASS_METHOD, incoming_sock,
                                                          fake_ttl=FAKE_TTL,
                                                          ip_frag_offset=IP_FRAG_OFFSET,
                                                          urgent_pointer_size=URGENT_POINTER_SIZE,
                                                          fake_inject_delay=FAKE_INJECT_DELAY)
            with _connections_lock:
                fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
            # Initiate TCP connection to the remote server
            try:
                await loop.sock_connect(outgoing_sock, (_connect_ip, CONNECT_PORT))
            except Exception:
                metrics.connect_failed()
                fake_injective_conn.monitor = False
                with _connections_lock:
                    fake_injective_connections.pop(fake_injective_conn.id, None)
                outgoing_sock.close()
                incoming_sock.close()
                return

            # Wait for the packet injector thread to confirm the fake data was acknowledged
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), BYPASS_TIMEOUT)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ValueError("unexpected close")
                if fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                    pass
                else:
                    logger.error("Unexpected t2a message: %s", fake_injective_conn.t2a_msg)
                    raise ValueError(f"unexpected t2a msg: {fake_injective_conn.t2a_msg}")
            except Exception:
                if not fake_injective_conn.bypass_counted:
                    fake_injective_conn.bypass_counted = True
                    metrics.bypass_failed()
                fake_injective_conn.monitor = False
                with _connections_lock:
                    fake_injective_connections.pop(fake_injective_conn.id, None)
                outgoing_sock.close()
                incoming_sock.close()
                return

            # Bypass complete — stop monitoring
            fake_injective_conn.monitor = False
            with _connections_lock:
                fake_injective_connections.pop(fake_injective_conn.id, None)
            metrics.bypass_succeeded()

        # Start bidirectional relay between the incoming client and the outgoing server
        await relay_bidirectional(incoming_sock, outgoing_sock)



    except Exception:
        logger.exception("Unexpected error in connection handler")
    finally:
        for s in (incoming_sock, outgoing_sock):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass
        metrics.connection_ended()
        if _conn_semaphore is not None:
            _conn_semaphore.release()


def _format_bytes(n: int) -> str:
    """Format byte count as a human-readable string."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _make_metrics_panel(s: dict, prev_bytes: int, prev_time: float) -> Panel:
    """Build a Rich Panel with a metrics summary table."""
    uptime = int(s["uptime_seconds"])
    h, remainder = divmod(uptime, 3600)
    m, sec = divmod(remainder, 60)
    uptime_str = f"{h:02d}:{m:02d}:{sec:02d}"

    # Bandwidth rate
    elapsed = time.monotonic() - prev_time
    rate_bytes = max(0, s["bytes_relayed"] - prev_bytes)
    rate_mbps = (rate_bytes / elapsed / 1_000_000) if elapsed > 0 else 0.0
    rate_str = f"{rate_mbps:.2f} MB/s"

    # Bypass success percentage
    total_bypasses = s["successful_bypasses"] + s["failed_bypasses"]
    bypass_pct = (s["successful_bypasses"] / total_bypasses * 100) if total_bypasses > 0 else 0.0

    # Max connections label
    max_conn_str = str(MAX_CONNECTIONS) if MAX_CONNECTIONS > 0 else "∞"

    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style="bold cyan",
        expand=True,
        padding=(0, 2),
    )

    # Row 1: uptime / connections
    table.add_column("Uptime",        style="bold white",  justify="center")
    table.add_column("Active Conns",  style="cyan",        justify="center")
    table.add_column("Total Conns",   style="white",       justify="center")
    table.add_column("Max Conns",     style="dim",         justify="center")
    table.add_column("Bypass OK",     style="bold green",  justify="center")
    table.add_column("Bypass Fail",   style="bold red",    justify="center")
    table.add_column("Success Rate",  style="bold yellow", justify="center")
    table.add_column("Relayed",       style="yellow",      justify="center")
    table.add_column("Rate",          style="green",       justify="center")

    row_cells: list[Text | str] = [
        uptime_str,
        str(s["active_connections"]),
        str(s["total_connections"]),
        max_conn_str,
        str(s["successful_bypasses"]),
        str(s["failed_bypasses"]),
        f"{bypass_pct:.1f}%",
        _format_bytes(s["bytes_relayed"]),
        rate_str,
    ]
    table.add_row(*row_cells)

    # Error footer row (only if errors occurred)
    error_parts: list[str] = []
    if s["connect_failed"] > 0:
        error_parts.append(f"[red]Conn failures:[/red] {s['connect_failed']}")
    if s["relay_broken"] > 0:
        error_parts.append(f"[red]Relay broken:[/red] {s['relay_broken']}")
    if error_parts:
        error_footer = Text.from_markup("   ".join(error_parts))
        panel_content = Columns([table, Align(error_footer, vertical="middle")])
    else:
        panel_content = table

    subtitle_parts = [f"[dim]refreshes every {METRICS_INTERVAL}s · Ctrl+C to stop[/dim]"]
    if AUTO_SELECT_SNI and AUTO_SELECT_INTERVAL > 0 and _next_sni_refresh_time is not None:
        remaining = max(0, int(_next_sni_refresh_time - time.monotonic()))
        rm, rs = divmod(remaining, 60)
        subtitle_parts.append(f"[dim magenta]next SNI scan in {rm:02d}:{rs:02d}[/dim magenta]")
    elif AUTO_SELECT_SNI and AUTO_SELECT_INTERVAL > 0:
        subtitle_parts.append("[dim magenta]SNI scan running…[/dim magenta]")

    return Panel(
        panel_content,
        title="[bold cyan]Live Metrics[/bold cyan]",
        border_style="cyan",
        subtitle=" · ".join(subtitle_parts),
    )


# Module-level live dashboard handle — shared between _dashboard_loop and shutdown
_live_dashboard: Live | None = None

# Timestamp (monotonic) of when the next background SNI refresh scan will start.
# None while scanning is in progress or refresh is disabled.
_next_sni_refresh_time: float | None = None


async def _dashboard_loop(interval: int):
    """Live-updating metrics panel that refreshes in-place every `interval` seconds."""
    global _live_dashboard
    prev_bytes = 0
    prev_time = time.monotonic()

    with Live(
        _make_metrics_panel(metrics.snapshot(), prev_bytes, prev_time),
        console=console,
        refresh_per_second=4,
        transient=False,
    ) as live:
        _live_dashboard = live
        while True:
            await asyncio.sleep(interval)
            s = metrics.snapshot()
            live.update(_make_metrics_panel(s, prev_bytes, prev_time))
            prev_bytes = s["bytes_relayed"]
            prev_time = time.monotonic()


def _print_banner() -> None:
    """Print the startup banner with project info and current config."""
    bypass_color = {
        "wrong_seq": "yellow", "wrong_checksum": "yellow", "low_ttl": "yellow",
        "tcp_segmentation": "cyan", "duplicate_syn": "magenta",
        "ip_fragmentation": "magenta", "fake_rst": "red",
        "tls_record_frag": "cyan", "tcp_urgent_pointer": "red",
    }.get(BYPASS_METHOD, "white")

    max_conn_str = str(MAX_CONNECTIONS) if MAX_CONNECTIONS > 0 else "Unlimited"
    auto_str = (
        f"Every {AUTO_SELECT_INTERVAL} min" if AUTO_SELECT_SNI and AUTO_SELECT_INTERVAL > 0
        else ("Enabled (no refresh)" if AUTO_SELECT_SNI else "Disabled")
    )

    info_table = Table.grid(padding=(0, 2))
    info_table.add_column(style="dim cyan", justify="right")
    info_table.add_column(style="bold white")
    info_table.add_column(style="dim cyan", justify="right")
    info_table.add_column(style="bold white")

    info_table.add_row(
        "Listen",       f"{LISTEN_HOST}:{LISTEN_PORT}",
        "Bypass",       f"[{bypass_color}]{BYPASS_METHOD}[/{bypass_color}]",
    )
    info_table.add_row(
        "Max Conns",    max_conn_str,
        "TLS Probe",    "[green]on[/green]" if SCAN_TLS_PROBE else "[dim]off[/dim]",
    )
    info_table.add_row(
        "Auto-Select",  auto_str,
        "TTL Probe",    "[green]on[/green]" if SCAN_TTL_PROBE else "[dim]off[/dim]",
    )
    info_table.add_row(
        "Metrics",      f"every {METRICS_INTERVAL}s" if METRICS_INTERVAL > 0 else "disabled",
        "Cache TTL",    f"{SCAN_CACHE_TTL}s" if SCAN_CACHE_TTL > 0 else "disabled",
    )

    console.print()
    console.print(Panel(
        Columns([info_table], expand=False),
        title="[bold cyan]SNI-Proxy[/bold cyan]",
        subtitle="[dim]DPI Bypass via Fake TLS ClientHello · WinDivert[/dim]",
        border_style="bright_cyan",
        expand=False,
    ))
    console.print()


def _print_proxy_ready() -> None:
    """Print the 'proxy ready' panel after SNI selection and injector startup."""
    table = Table.grid(padding=(0, 2))
    table.add_column(style="dim cyan", justify="right")
    table.add_column(style="bold white")

    table.add_row("Listening on",   f"[bold]{LISTEN_HOST}:{LISTEN_PORT}[/bold]")
    table.add_row("SNI  →  IP",     f"[bold green]{FAKE_SNI_STR}[/bold green] [dim]→[/dim] [cyan]{CONNECT_IP}[/cyan]")
    table.add_row("Bypass method",  f"[yellow]{BYPASS_METHOD}[/yellow]")
    table.add_row("Interface IP",   f"[dim]{INTERFACE_IPV4}[/dim]")

    console.print(Panel(
        table,
        title="[bold green]Proxy Ready[/bold green]",
        border_style="green",
        expand=False,
    ))
    console.print()


async def main():
    """Main async entry point: creates the listening socket and accepts incoming connections."""
    # Start metrics dashboard if enabled
    if METRICS_INTERVAL > 0:
        asyncio.create_task(_dashboard_loop(METRICS_INTERVAL))

    # Create the listening (mother) socket with TCP keep-alive
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
    mother_sock.listen()
    loop = asyncio.get_running_loop()

    # Suppress the benign Windows IOCP "WinError 6: The handle is invalid" noise that
    # asyncio logs when it tries to cancel an overlapped I/O operation on a socket that
    # was already closed (our relay_bidirectional closes sockets before cancelling tasks).
    def _exception_handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
        exc = context.get("exception")
        if (
            isinstance(exc, OSError)
            and getattr(exc, "winerror", None) == 6
            and "Cancelling an overlapped future" in context.get("message", "")
        ):
            return  # Expected on Windows when socket is closed before task cancel
        loop.default_exception_handler(context)

    loop.set_exception_handler(_exception_handler)

    # Accept loop: each incoming connection is handled concurrently as an async task
    while True:
        incoming_sock, addr = await loop.sock_accept(mother_sock)
        incoming_sock.setblocking(False)
        incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, KEEPALIVE_IDLE)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, KEEPALIVE_INTERVAL)
        incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, KEEPALIVE_COUNT)
        incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, SOCKET_BUFFER_SIZE)
        incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, SOCKET_BUFFER_SIZE)
        asyncio.create_task(handle(incoming_sock, addr))


if __name__ == "__main__":
    # Create logs/ directory and open a timestamped log file for this session
    # (only when LOG_TO_FILE = true in config.toml).
    if LOG_TO_FILE:
        _setup_file_logging()

    # Print startup banner
    _print_banner()

    # Load sni_list.txt and let the user pick an SNI (required)
    select_sni_interactive()

    # Validate resolved IPs before building WinDivert filter
    try:
        ipaddress.IPv4Address(CONNECT_IP)
        ipaddress.IPv4Address(INTERFACE_IPV4)
    except ValueError as e:
        logger.critical("Invalid IP address: %s", e)
        sys.exit(1)

    # Start the packet injector in a background daemon thread (intercepts packets via WinDivert)
    _restart_injector()

    # Start background SNI refresh thread if auto-select is enabled and interval is set
    if AUTO_SELECT_SNI and AUTO_SELECT_INTERVAL > 0:
        logger.info(
            "Background SNI refresh enabled: scanning every %d minute(s).",
            AUTO_SELECT_INTERVAL,
        )
        threading.Thread(target=_background_sni_refresh, daemon=True).start()

    # Print proxy-ready panel
    _print_proxy_ready()

    # Run the async proxy server
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # Stop the live panel cleanly before printing the shutdown summary
        if _live_dashboard is not None:
            try:
                _live_dashboard.stop()
            except Exception:
                pass
        s = metrics.snapshot()
        bypass_total = s["successful_bypasses"] + s["failed_bypasses"]
        bypass_pct = (s["successful_bypasses"] / bypass_total * 100) if bypass_total > 0 else 0.0

        summary = Table.grid(padding=(0, 2))
        summary.add_column(style="dim cyan", justify="right")
        summary.add_column(style="bold white")
        summary.add_row("Total connections", str(s["total_connections"]))
        summary.add_row(
            "DPI Bypasses",
            f"[green]{s['successful_bypasses']} ok[/green]  [red]{s['failed_bypasses']} failed[/red]  "
            f"[yellow]({bypass_pct:.1f}% success)[/yellow]"
        )
        summary.add_row("Data relayed",      _format_bytes(s["bytes_relayed"]))
        if s["connect_failed"] > 0:
            summary.add_row("Conn failures",  f"[red]{s['connect_failed']}[/red]")
        if s["relay_broken"] > 0:
            summary.add_row("Relay broken",   f"[red]{s['relay_broken']}[/red]")

        console.print()
        console.print(Panel(
            summary,
            title="[bold yellow]Session Summary[/bold yellow]",
            border_style="yellow",
            expand=False,
        ))
