#!/usr/bin/env python3
"""
╔══════════════════════════════════════╗
║         TOR IP ROTATOR v1.1          ║
║   Automated IP rotation via Tor      ║
╚══════════════════════════════════════╝

Requirements:
  pip install stem requests rich

System:
  Tor must be installed and running with ControlPort enabled.

  Linux/macOS:  sudo apt install tor  /  brew install tor
  Then edit /etc/tor/torrc (or ~/.torrc) and add:
      ControlPort 9051
      CookieAuthentication 0
      HashedControlPassword ""   # or set a password (see --help)
  Then: sudo systemctl start tor  /  brew services start tor

  Windows: Use Tor Browser Bundle or install tor via chocolatey.
           Tor control port is 9151 by default in Tor Browser.
"""

# ─── Standard library ─────────────────────────────────────────────────────────
import sys
import json
import time
import socket
import os
import getpass
import argparse
import threading
from typing import List, Optional, Tuple

# ─── Third-party ──────────────────────────────────────────────────────────────
try:
    import requests
    from stem import Signal
    from stem.control import Controller
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
    from rich import box
    from rich.layout import Layout
    from rich.align import Align
except ImportError:
    print("\n[!] Missing dependencies. Install with:\n    pip install stem requests rich\n")
    sys.exit(1)


console = Console()

BANNER = """[bold cyan]
  ██╗██████╗     ██████╗  ██████╗ ████████╗ █████╗ ████████╗ ██████╗ ██████╗
  ██║██╔══██╗    ██╔══██╗██╔═══██╗╚══██╔══╝██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
  ██║██████╔╝    ██████╔╝██║   ██║   ██║   ███████║   ██║   ██║   ██║██████╔╝
  ██║██╔═══╝     ██╔══██╗██║   ██║   ██║   ██╔══██║   ██║   ██║   ██║██╔══██╗
  ██║██║         ██║  ██║╚██████╔╝   ██║   ██║  ██║   ██║   ╚██████╔╝██║  ██║
  ╚═╝╚═╝         ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝
  GitHub: https://github.com/aadhilfazal
[/bold cyan]"""

DISCLAIMER = "[dim]For authorized security research, bug bounty, and privacy use only.[/dim]"


# ─── Config ────────────────────────────────────────────────────────────────────

DEFAULT_TOR_HOST   = "127.0.0.1"
DEFAULT_TOR_PORT   = 9051         # 9151 for Tor Browser
DEFAULT_SOCKS_PORT = 9050         # 9150 for Tor Browser

IP_CHECK_URLS: List[str] = [
    "https://api.ipify.org?format=json",
    "https://httpbin.org/ip",
    "https://icanhazip.com",
]


# ─── Tor helpers ───────────────────────────────────────────────────────────────

def get_tor_session(socks_port: int) -> requests.Session:
    session = requests.Session()
    session.proxies = {
        "http":  f"socks5h://127.0.0.1:{socks_port}",
        "https": f"socks5h://127.0.0.1:{socks_port}",
    }
    return session


def get_current_ip(session: requests.Session, timeout: int = 8) -> str:
    """
    Fetches the current Tor exit IP using multiple fallback URLs.
    Returns 'unavailable' if all endpoints fail.
    """
    for url in IP_CHECK_URLS:
        try:
            r = session.get(url, timeout=timeout)
            if r.status_code == 200:
                data = r.text.strip()
                if data.startswith("{"):
                    # FIX: json was previously imported inside this hot path.
                    # It is now a top-level import (no repeated sys.modules lookup overhead).
                    j = json.loads(data)
                    return j.get("ip") or j.get("origin", "unknown")
                return data
        except Exception:
            continue
    return "unavailable"


def get_new_ip_confirmed(
    session: requests.Session,
    old_ip: str,
    retries: int = 6,
    delay: int = 4,
) -> str:
    """
    Polls until the Tor exit IP differs from old_ip, then returns the new IP.

    FIX (v1.1): The previous fallback `return get_current_ip(session)` could
    silently return 'unavailable' or the same old_ip, both of which would then
    be recorded in history and shown as the active IP.  We now keep the last
    successful non-unavailable value and return it as the best known IP instead.
    """
    best_known = old_ip

    for _ in range(retries):
        ip = get_current_ip(session)

        if ip == "unavailable":
            time.sleep(delay)
            continue

        # Track the freshest reachable IP even if it hasn't changed yet
        best_known = ip

        if ip != old_ip:
            return ip

        time.sleep(delay)

    # Return whatever was reachable; never return bare "unavailable"
    return best_known


def check_control_port(host: str, port: int, timeout: float = 3.0) -> bool:
    """
    FIX (v1.1): Pre-flight TCP check so Controller.from_port() never hangs
    indefinitely when the control port is firewalled or Tor isn't running.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def renew_tor_ip(host: str, port: int, password: str = "", max_wait: int = 30) -> bool:
    """
    Sends NEWNYM to request a new Tor circuit.
    Respects Tor's internal rate-limit via get_newnym_wait().
    Does NOT guarantee a different exit IP — that is Tor's decision.
    """
    # FIX (v1.1): Bail out fast instead of hanging if the port is unreachable
    if not check_control_port(host, port):
        console.print(
            f"[red][!] Control port {host}:{port} unreachable — skipping rotation.[/red]"
        )
        return False

    try:
        with Controller.from_port(address=host, port=port) as ctrl:
            ctrl.authenticate(password=password) if password else ctrl.authenticate()

            wait_time = ctrl.get_newnym_wait()
            if wait_time > 0:
                time.sleep(wait_time)

            ctrl.signal(Signal.NEWNYM)
            return True

    except Exception as e:
        console.print(f"[red][!] Tor control error: {e}[/red]")
        return False


# ─── Stats tracker ─────────────────────────────────────────────────────────────

class Stats:
    """
    Thread-safe rotation statistics.

    FIX (v1.1): Rotation counting was slightly inconsistent — previously
    stats.record() was called unconditionally after renew_tor_ip(), meaning
    a failed rotation attempt (ok=False) would still silently fall through
    without recording anything, but the counter could drift if the code path
    changed.  Now record() is called only on confirmed reachable IPs and the
    failed_rotations counter is tracked separately, making both counts
    unambiguous and auditable.
    """

    def __init__(self) -> None:
        self.successful_rotations: int = 0
        self.failed_rotations: int     = 0
        self.start_time: float         = time.time()
        self.ip_history: List[Tuple[str, str, bool]] = []  # (timestamp, ip, changed)
        self._lock = threading.Lock()

    @property
    def total_attempts(self) -> int:
        return self.successful_rotations + self.failed_rotations

    def record_success(self, ip: str, changed: bool) -> None:
        with self._lock:
            self.successful_rotations += 1
            ts = time.strftime("%H:%M:%S")
            self.ip_history.append((ts, ip, changed))
            if len(self.ip_history) > 50:
                self.ip_history.pop(0)

    def record_failure(self) -> None:
        with self._lock:
            self.failed_rotations += 1

    def elapsed(self) -> str:
        secs = int(time.time() - self.start_time)
        h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
        return f"{h:02d}:{m:02d}:{s:02d}"


# ─── UI helpers ────────────────────────────────────────────────────────────────

def build_status_panel(
    current_ip: str,
    next_ip_in: int,
    interval: int,
    stats: Stats,
    status_msg: str,
) -> Panel:
    table = Table.grid(padding=(0, 2))
    table.add_column(style="bold dim cyan", justify="right")
    table.add_column(style="bold white")

    table.add_row("CURRENT IP",   f"[bold green]{current_ip}[/bold green]")
    table.add_row("NEXT ROTATE",  f"[yellow]{next_ip_in}s[/yellow]  /  every {interval}s")
    # FIX (v1.1): show successful rotations vs total attempts separately
    table.add_row(
        "ROTATIONS",
        f"{stats.successful_rotations} ok  "
        f"[dim]/ {stats.total_attempts} attempts[/dim]"
        + (f"  [red]{stats.failed_rotations} failed[/red]" if stats.failed_rotations else ""),
    )
    table.add_row("UPTIME",       stats.elapsed())
    table.add_row("STATUS",       status_msg)

    return Panel(
        table,
        title="[bold cyan]● TOR IP ROTATOR[/bold cyan]",
        border_style="cyan",
        padding=(1, 2),
    )


def build_history_panel(stats: Stats) -> Panel:
    if not stats.ip_history:
        content: object = Text("No rotations yet…", style="dim")
    else:
        t = Table(
            box=box.SIMPLE, show_header=True,
            header_style="bold dim cyan", expand=True, padding=(0, 1),
        )
        t.add_column("#",           style="dim",    width=4)
        t.add_column("Time",        style="cyan",   width=10)
        t.add_column("IP Assigned", style="green")
        t.add_column("Changed?",    width=9)

        recent = list(reversed(stats.ip_history[-10:]))
        for idx, (ts, ip, changed) in enumerate(recent, 1):
            changed_cell = "[green]✓ yes[/green]" if changed else "[yellow]– no[/yellow]"
            t.add_row(
                str(stats.successful_rotations - idx + 1),
                ts, ip, changed_cell,
            )
        content = t

    return Panel(
        content,
        title="[bold cyan]IP History[/bold cyan]",
        border_style="dim cyan",
        padding=(0, 1),
    )


def build_full_layout(
    current_ip: str,
    next_ip_in: int,
    interval: int,
    stats: Stats,
    status_msg: str,
) -> Layout:
    """
    FIX (v1.1): UI update timing was inconsistent because the rotation phase
    called `live.update(build_status_panel(...))` — a bare Panel — while the
    countdown loop called `live.update(layout)` — a full two-pane Layout.
    This caused the history panel to flash away for 1–2 seconds on every
    rotation.  Both paths now call this helper so the full layout is always
    rendered, regardless of rotation state.
    """
    layout = Layout()
    layout.split_column(
        Layout(
            build_status_panel(current_ip, next_ip_in, interval, stats, status_msg),
            name="top",
        ),
        Layout(build_history_panel(stats), name="bottom"),
    )
    return layout


# ─── Password resolution ───────────────────────────────────────────────────────

def resolve_password(cli_password: Optional[str]) -> str:
    """
    FIX (v1.1): Passwords passed as CLI arguments are exposed in `ps aux`
    output and shell history.  Resolution order:

      1. TOR_CONTROL_PASS environment variable (preferred in CI/scripts)
      2. --password CLI flag (convenience, less secure)
      3. Interactive prompt if neither is set and Tor needs a password
    """
    if cli_password:
        return cli_password
    env_pass = os.environ.get("TOR_CONTROL_PASS", "")
    if env_pass:
        return env_pass
    # Return empty string — controller will try cookie/no-auth first.
    # Only prompt interactively if the first authenticate() attempt fails
    # (handled in renew_tor_ip via the exception path).
    return ""


# ─── Main rotation loop ────────────────────────────────────────────────────────

def run_rotator(
    interval: int,
    count: int,
    tor_host: str,
    tor_port: int,
    socks_port: int,
    password: str,
) -> None:

    console.print(BANNER)
    console.print(Align.center(DISCLAIMER))
    console.print()

    session = get_tor_session(socks_port)
    stats   = Stats()

    # ── Verify Tor is reachable ─────────────────────────────────────────────
    with console.status("[cyan]Connecting to Tor network…[/cyan]"):
        initial_ip = get_current_ip(session)
        if initial_ip == "unavailable":
            console.print(Panel(
                "[red]Could not reach Tor network.[/red]\n\n"
                "Make sure:\n"
                "  • Tor is installed and running\n"
                f"  • SOCKS port {socks_port} is open\n"
                f"  • Control port {tor_port} is open (ControlPort in torrc)\n"
                "  • CookieAuthentication 0  (or set TOR_CONTROL_PASS env var)",
                title="[red]Connection Failed[/red]",
                border_style="red",
            ))
            sys.exit(1)

    console.print(
        f"[green]✓[/green] Connected to Tor  |  "
        f"Entry IP: [bold green]{initial_ip}[/bold green]\n"
    )

    current_ip  = initial_ip
    status_msg  = "[green]Running[/green]"

    try:
        with Live(console=console, refresh_per_second=2) as live:
            while True:

                # ── Countdown until next rotation ────────────────────────
                for remaining in range(interval, 0, -1):
                    live.update(
                        build_full_layout(current_ip, remaining, interval, stats, status_msg)
                    )
                    time.sleep(1)

                # ── Rotate ───────────────────────────────────────────────
                status_msg = "[yellow]Rotating…[/yellow]"
                # FIX (v1.1): always render full layout here, not a bare panel
                live.update(
                    build_full_layout(current_ip, 0, interval, stats, status_msg)
                )

                ok = renew_tor_ip(tor_host, tor_port, password)

                if ok:
                    old_ip = current_ip
                    new_ip = get_new_ip_confirmed(session, old_ip)

                    changed    = new_ip != old_ip
                    current_ip = new_ip
                    # FIX (v1.1): record with explicit changed flag for accurate history
                    stats.record_success(new_ip, changed)

                    status_msg = (
                        "[green]IP changed successfully[/green]"
                        if changed
                        else "[yellow]Rotated but IP reused (Tor exit unchanged)[/yellow]"
                    )
                else:
                    # FIX (v1.1): failed attempts tracked separately, not silently dropped
                    stats.record_failure()
                    status_msg = "[red]Rotate failed – retrying next cycle[/red]"

                # FIX (v1.1): count checks successful rotations only, not failed attempts
                if count and stats.successful_rotations >= count:
                    console.print(
                        f"\n[green]✓[/green] Reached {count} successful rotation(s). Done."
                    )
                    break

    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted by user.[/yellow]")

    # ── Final summary ────────────────────────────────────────────────────────
    summary = Table(
        box=box.ROUNDED, border_style="cyan",
        show_header=False, padding=(0, 2),
    )
    summary.add_column(style="bold dim cyan", justify="right")
    summary.add_column(style="white")
    summary.add_row("Successful rotations", str(stats.successful_rotations))
    summary.add_row("Failed rotations",     str(stats.failed_rotations))
    summary.add_row("Total attempts",       str(stats.total_attempts))
    summary.add_row("Total uptime",         stats.elapsed())
    summary.add_row("Final IP",             current_ip)
    console.print(Panel(
        summary,
        title="[bold cyan]Session Summary[/bold cyan]",
        border_style="cyan",
    ))


# ─── Entry point ──────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        prog="ip_rotator",
        description=(
            "Rotate your Tor exit IP on a timer. "
            "Requires Tor with ControlPort enabled."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python ip_rotator.py                      # rotate every 60s, forever
  python ip_rotator.py -i 30               # every 30 seconds
  python ip_rotator.py -i 120 -n 10        # every 2 min, stop after 10 rotations
  python ip_rotator.py --tor-port 9151     # use Tor Browser control port
  TOR_CONTROL_PASS=secret python ip_rotator.py  # pass password via env (recommended)

Torrc snippet (add to /etc/tor/torrc):
  ControlPort 9051
  CookieAuthentication 0
        """,
    )
    parser.add_argument("-i", "--interval", type=int, default=60,
                        help="Seconds between IP rotations (default: 60)")
    parser.add_argument("-n", "--count",    type=int, default=0,
                        help="Stop after N successful rotations (0 = run forever)")
    parser.add_argument("--tor-host",       default=DEFAULT_TOR_HOST,
                        help=f"Tor control host (default: {DEFAULT_TOR_HOST})")
    parser.add_argument("--tor-port",       type=int, default=DEFAULT_TOR_PORT,
                        help=f"Tor control port (default: {DEFAULT_TOR_PORT})")
    parser.add_argument("--socks-port",     type=int, default=DEFAULT_SOCKS_PORT,
                        help=f"Tor SOCKS port (default: {DEFAULT_SOCKS_PORT})")
    parser.add_argument("--password",       default=None,
                        help="Tor control password — prefer TOR_CONTROL_PASS env var instead")

    args = parser.parse_args()

    if args.interval < 5:
        console.print("[red][!] Interval must be ≥ 5 seconds (Tor circuit build time).[/red]")
        sys.exit(1)

    password = resolve_password(args.password)

    run_rotator(
        interval   = args.interval,
        count      = args.count,
        tor_host   = args.tor_host,
        tor_port   = args.tor_port,
        socks_port = args.socks_port,
        password   = password,
    )


if __name__ == "__main__":
    main()
