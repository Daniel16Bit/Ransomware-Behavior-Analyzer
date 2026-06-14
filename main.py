#!/usr/bin/env python3
"""
main.py - Ransomware Behavior Analyzer
ASCII hacker-style terminal UI (curses)

Linux-only. Requires:
  pip install watchdog psutil
  gcc -O2 -shared -fPIC -o entropy_calc.so entropy_calc.c -lm
"""

import curses
import time
import os
import sys
import signal
import threading
from datetime import datetime

import config
import logger
import allowlist
from detector import BehaviorEngine
from monitor import start_monitor
from net_monitor import NetworkMonitor
import proc_monitor


# ════════════════════════════════════════════════════════════════
# ASCII ART & CONSTANTS
# ════════════════════════════════════════════════════════════════

BANNER = [
    "██████╗  █████╗ ███╗  ██╗███████╗ ██████╗ ███╗  ███╗",
    "██╔══██╗██╔══██╗████╗ ██║██╔════╝██╔═══██╗████╗████║",
    "██████╔╝███████║██╔██╗██║███████╗██║   ██║██╔████╔██║",
    "██╔══██╗██╔══██║██║╚████║╚════██║██║   ██║██║╚██╔╝██║",
    "██║  ██║██║  ██║██║ ╚███║███████║╚██████╔╝██║ ╚═╝ ██║",
    "╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝",
]
SUBTITLE = "[ BEHAVIORAL RANSOMWARE ANALYZER v2.0 :: Linux Edition ]"

SEV_SYMBOL = {
    "INFO":     ("·",  1),   # cyan
    "WARN":     ("▲",  3),   # yellow
    "ALERT":    ("■",  4),   # red
    "CRITICAL": ("◆",  5),   # magenta+bold
}

# curses color pair IDs
C_GREEN   = 1
C_CYAN    = 2
C_YELLOW  = 3
C_RED     = 4
C_MAGENTA = 5
C_WHITE   = 6
C_DGRAY   = 7

HELP_TEXT = (
    " [Q]uit  [R]eset score  [A]llowlist  [K]ill mode  [S]uspend mode  "
    "[TAB]switch panel  [↑↓]scroll"
)


# ════════════════════════════════════════════════════════════════
# HELPER DRAWING FUNCTIONS
# ════════════════════════════════════════════════════════════════

def _safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x >= w:
        return
    if x < 0:
        text = text[-x:]
        x = 0
    text = text[: w - x - 1]
    if not text:
        return
    try:
        win.addstr(y, x, text, attr)
    except curses.error:
        pass


def _hline(win, y, x, char, length, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h:
        return
    length = min(length, w - x - 1)
    try:
        win.addstr(y, x, char * length, attr)
    except curses.error:
        pass


def _threat_bar(score: int, width: int = 35) -> tuple[str, int]:
    """Returns (bar_string, color_pair)."""
    filled = int((score / 100) * width)
    bar    = "█" * filled + "░" * (width - filled)
    color  = (C_RED if score > 70 else C_YELLOW if score > 40 else C_GREEN)
    return f"[{bar}] {score:3d}%", color


def _score_sparkline(history: list, width: int = 40) -> str:
    """Render a mini sparkline of score history."""
    SPARKS = " ▁▂▃▄▅▆▇█"
    if not history:
        return "─" * width
    vals = [s for _, s in history]
    # Sample to fit width
    if len(vals) > width:
        step = len(vals) / width
        vals = [vals[int(i * step)] for i in range(width)]
    line = ""
    for v in vals:
        idx = int((v / 100) * (len(SPARKS) - 1))
        line += SPARKS[idx]
    # pad/truncate
    return line[:width].ljust(width, "─")


def _format_ip(ip: str) -> str:
    return ip if ip else "0.0.0.0"


# ════════════════════════════════════════════════════════════════
# PANEL: HEADER
# ════════════════════════════════════════════════════════════════

def draw_header(stdscr, engine: BehaviorEngine, watch_path: str, row: int) -> int:
    h, w = stdscr.getmaxyx()
    b_attr = curses.color_pair(C_GREEN) | curses.A_BOLD

    # Banner (centered)
    for i, line in enumerate(BANNER):
        cx = max(0, (w - len(line)) // 2)
        _safe_addstr(stdscr, row + i, cx, line[:w-1], b_attr)
    row += len(BANNER)

    cx = max(0, (w - len(SUBTITLE)) // 2)
    _safe_addstr(stdscr, row, cx, SUBTITLE,
                 curses.color_pair(C_CYAN) | curses.A_BOLD)
    row += 1
    _hline(stdscr, row, 0, "═", w - 1, curses.color_pair(C_GREEN))
    row += 1

    # Threat score bar
    score        = engine.get_score()
    bar, bcolor  = _threat_bar(score, min(40, w // 3))
    _safe_addstr(stdscr, row, 1,
                 f" THREAT SCORE: {bar}",
                 curses.color_pair(bcolor) | curses.A_BOLD)

    # Timestamp (right side)
    ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
    _safe_addstr(stdscr, row, w - len(ts) - 2, ts,
                 curses.color_pair(C_CYAN))
    row += 1

    # Sparkline
    history = engine.get_score_history()
    spark   = _score_sparkline(history, width=min(60, w - 20))
    _safe_addstr(stdscr, row, 1,
                 f" SCORE HISTORY: {spark}",
                 curses.color_pair(C_YELLOW))
    row += 1

    # Status line
    stats    = logger.get_stats()
    info_cnt = stats["by_severity"].get("INFO",     0)
    warn_cnt = stats["by_severity"].get("WARN",     0)
    alrt_cnt = stats["by_severity"].get("ALERT",    0)
    crit_cnt = stats["by_severity"].get("CRITICAL", 0)

    mode_str = ""
    if config.AUTO_KILL_ENABLED:
        mode_str += " [AUTO-KILL:ON]"
    if config.SUSPEND_ENABLED:
        mode_str += " [AUTO-SUSPEND:ON]"

    status = (
        f" WATCH: {watch_path}  "
        f"│ INFO:{info_cnt} WARN:{warn_cnt} ALERT:{alrt_cnt} CRIT:{crit_cnt}"
        f"{mode_str}"
    )
    _safe_addstr(stdscr, row, 0, status[:w-1], curses.color_pair(C_CYAN))
    row += 1
    _hline(stdscr, row, 0, "─", w - 1, curses.color_pair(C_GREEN))
    row += 1
    return row


# ════════════════════════════════════════════════════════════════
# PANEL: EVENT LOG
# ════════════════════════════════════════════════════════════════

def draw_event_log(stdscr, start_row: int, end_row: int, scroll: int):
    h, w = stdscr.getmaxyx()
    visible = end_row - start_row

    _safe_addstr(stdscr, start_row, 1,
                 "┌─ EVENT LOG " + "─" * max(0, w - 15) + "┐",
                 curses.color_pair(C_GREEN))
    start_row += 1

    events   = logger.get_events(200)
    total    = len(events)
    # scroll: 0 = newest at bottom
    offset   = max(0, total - visible - scroll)
    visible_events = events[offset: offset + visible]

    for i, ev in enumerate(visible_events):
        row = start_row + i
        if row >= end_row:
            break

        sev          = ev.get("severity", "INFO")
        sym, cpair   = SEV_SYMBOL.get(sev, ("?", C_WHITE))
        ts           = ev.get("ts", "")[-15:-4]   # HH:MM:SS.mmm → HH:MM:SS
        if len(ts) > 8:
            ts = ts[:8]
        event_type   = ev.get("event", "")[:20]
        filepath     = os.path.basename(ev.get("file", ""))[:24]
        details      = ev.get("details", {})
        pid_str      = f" PID:{ev['pid']}" if "pid" in ev else ""

        # Build detail summary
        if "entropy" in details:
            det = f"H={details['entropy']:.3f}"
        elif "count" in details:
            det = f"n={details['count']}"
        elif "extension" in details:
            det = details["extension"]
        elif "remote_ip" in details:
            det = f"{details['remote_ip']}:{details.get('remote_port','?')}"
        else:
            det = str(details)[:25]

        attr = curses.color_pair(cpair)
        if sev == "CRITICAL":
            attr |= curses.A_BOLD

        line = f"│{sym} [{ts}] {event_type:<21s} {filepath:<25s}{pid_str:<9s} {det}"
        _safe_addstr(stdscr, row, 0, line[:w-1], attr)

    # Empty lines
    for i in range(len(visible_events), visible):
        _safe_addstr(stdscr, start_row + i, 0, "│" + " " * (w - 2),
                     curses.color_pair(C_DGRAY))

    scroll_info = f" [{offset+1}-{min(offset+visible, total)}/{total}] "
    _safe_addstr(stdscr, end_row, 1,
                 "└" + scroll_info + "─" * max(0, w - len(scroll_info) - 3) + "┘",
                 curses.color_pair(C_GREEN))


# ════════════════════════════════════════════════════════════════
# PANEL: NETWORK CONNECTIONS
# ════════════════════════════════════════════════════════════════

def draw_network_panel(stdscr, net_monitor: NetworkMonitor,
                       start_row: int, end_row: int):
    w = stdscr.getmaxyx()[1]
    _safe_addstr(stdscr, start_row, 1,
                 "┌─ ACTIVE CONNECTIONS " + "─" * max(0, w - 24) + "┐",
                 curses.color_pair(C_CYAN))
    start_row += 1

    conns   = net_monitor.get_active_connections()
    visible = end_row - start_row

    if not conns:
        _safe_addstr(stdscr, start_row, 2,
                     "No active external connections",
                     curses.color_pair(C_DGRAY))
    else:
        header = f"│ {'REMOTE IP':<18} {'R.PORT':>6}  {'L.PORT':>6}  {'STATE':<13}"
        _safe_addstr(stdscr, start_row, 0, header[:w-1],
                     curses.color_pair(C_WHITE) | curses.A_BOLD)
        start_row += 1

        for i, c in enumerate(conns[:visible - 1]):
            row   = start_row + i
            r_ip  = c["remote_ip"]
            color = C_RED if not _is_private_safe(r_ip) else C_CYAN
            line  = (f"│ {r_ip:<18} {c['remote_port']:>6}  "
                     f"{c['local_port']:>6}  ESTABLISHED")
            _safe_addstr(stdscr, row, 0, line[:w-1],
                         curses.color_pair(color))

    _safe_addstr(stdscr, end_row, 1,
                 "└" + "─" * max(0, w - 3) + "┘",
                 curses.color_pair(C_CYAN))


def _is_private_safe(ip: str) -> bool:
    import struct, socket
    try:
        packed = struct.unpack("!I", socket.inet_aton(ip))[0]
        for (net, mask) in config.PRIVATE_RANGES:
            if (packed & mask) == net:
                return True
    except Exception:
        pass
    return False


# ════════════════════════════════════════════════════════════════
# PANEL: TOP PROCESSES
# ════════════════════════════════════════════════════════════════

def draw_proc_panel(stdscr, start_row: int, end_row: int):
    w = stdscr.getmaxyx()[1]
    _safe_addstr(stdscr, start_row, 1,
                 "┌─ TOP PROCESSES (by FD count) " + "─" * max(0, w - 33) + "┐",
                 curses.color_pair(C_YELLOW))
    start_row += 1
    visible = end_row - start_row

    procs   = proc_monitor.get_all_procs()
    procs   = sorted(procs, key=lambda p: p.get("fd_count", 0), reverse=True)
    allowed = allowlist.get_all()

    header = f"│ {'PID':>6} {'COMM':<16} {'STATE':>5} {'FDs':>5} {'RSS(KB)':>8}  EXE"
    _safe_addstr(stdscr, start_row, 0, header[:w-1],
                 curses.color_pair(C_WHITE) | curses.A_BOLD)
    start_row += 1

    for i, p in enumerate(procs[: visible - 1]):
        row   = start_row + i
        exe   = p.get("exe", "")
        color = C_DGRAY
        if p.get("fd_count", 0) >= config.HIGH_FD_COUNT_THRESHOLD:
            color = C_RED
        elif p.get("fd_count", 0) >= config.HIGH_FD_COUNT_THRESHOLD // 2:
            color = C_YELLOW

        line = (f"│ {p['pid']:>6} {p['comm']:<16} {p['state']:>5} "
                f"{p['fd_count']:>5} {p['vm_rss_kb']:>8}  "
                f"{os.path.basename(exe)[:20]}")
        _safe_addstr(stdscr, row, 0, line[:w-1], curses.color_pair(color))

    _safe_addstr(stdscr, end_row, 1,
                 "└" + "─" * max(0, w - 3) + "┘",
                 curses.color_pair(C_YELLOW))


# ════════════════════════════════════════════════════════════════
# MAIN UI LOOP
# ════════════════════════════════════════════════════════════════

def draw_ui(stdscr, engine: BehaviorEngine,
            net_monitor: NetworkMonitor, watch_path: str):
    # ── curses setup ──────────────────────────────────────────────
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(C_GREEN,   curses.COLOR_GREEN,   -1)
    curses.init_pair(C_CYAN,    curses.COLOR_CYAN,    -1)
    curses.init_pair(C_YELLOW,  curses.COLOR_YELLOW,  -1)
    curses.init_pair(C_RED,     curses.COLOR_RED,     -1)
    curses.init_pair(C_MAGENTA, curses.COLOR_MAGENTA, -1)
    curses.init_pair(C_WHITE,   curses.COLOR_WHITE,   -1)
    curses.init_pair(C_DGRAY,   curses.COLOR_BLACK,   -1)

    curses.curs_set(0)
    stdscr.nodelay(True)
    stdscr.keypad(True)

    active_panel = 0   # 0=events, 1=network, 2=processes
    scroll       = 0
    panels       = ["EVENTS", "NETWORK", "PROCESSES"]

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        # ── Header ────────────────────────────────────────────────
        content_start = draw_header(stdscr, engine, watch_path, 0)

        # ── Panel tabs ────────────────────────────────────────────
        tab_row = content_start
        tab_str = ""
        for i, name in enumerate(panels):
            if i == active_panel:
                tab_str += f"[■ {name}]"
            else:
                tab_str += f"[  {name}]"
        _safe_addstr(stdscr, tab_row, 1, tab_str,
                     curses.color_pair(C_WHITE) | curses.A_BOLD)
        content_start += 1

        # ── Footer ────────────────────────────────────────────────
        footer_row = h - 1
        _safe_addstr(stdscr, footer_row, 0, HELP_TEXT[:w-1],
                     curses.color_pair(C_GREEN))

        # ── Main panel ───────────────────────────────────────────
        panel_end = footer_row - 1
        if content_start < panel_end:
            if active_panel == 0:
                draw_event_log(stdscr, content_start, panel_end, scroll)
            elif active_panel == 1:
                draw_network_panel(stdscr, net_monitor,
                                   content_start, panel_end)
            elif active_panel == 2:
                draw_proc_panel(stdscr, content_start, panel_end)

        stdscr.refresh()

        # ── Input ─────────────────────────────────────────────────
        key = stdscr.getch()
        if key in (ord('q'), ord('Q')):
            break
        elif key in (ord('r'), ord('R')):
            engine.reset_score()
            logger.clear_events()
        elif key == ord('\t'):
            active_panel = (active_panel + 1) % len(panels)
            scroll = 0
        elif key == curses.KEY_UP:
            scroll = min(scroll + 1, 200)
        elif key == curses.KEY_DOWN:
            scroll = max(scroll - 1, 0)
        elif key in (ord('k'), ord('K')):
            config.AUTO_KILL_ENABLED = not config.AUTO_KILL_ENABLED
            logger.log_event("INFO", "CONFIG_CHANGE", "",
                             {"auto_kill": config.AUTO_KILL_ENABLED})
        elif key in (ord('s'), ord('S')):
            config.SUSPEND_ENABLED = not config.SUSPEND_ENABLED
            logger.log_event("INFO", "CONFIG_CHANGE", "",
                             {"auto_suspend": config.SUSPEND_ENABLED})
        elif key in (ord('a'), ord('A')):
            # Print allowlist summary to log
            al = allowlist.get_all()
            logger.log_event("INFO", "ALLOWLIST_DUMP", "",
                             {"count": len(al), "hashes": list(al.keys())[:5]})

        time.sleep(1.0 / config.UI_REFRESH_HZ)


# ════════════════════════════════════════════════════════════════
# ENTRY POINT
# ════════════════════════════════════════════════════════════════

def main():
    print("\033[32m[*] Ransomware Behavior Analyzer starting...\033[0m")

    # ── Init subsystems ───────────────────────────────────────────
    os.makedirs(config.WATCH_PATH, exist_ok=True)
    os.makedirs(config.LOG_DIR,    exist_ok=True)
    os.makedirs(config.HASH_DIR,   exist_ok=True)

    allowlist.load()

    engine      = BehaviorEngine()
    net_monitor = NetworkMonitor(engine_callback=engine.on_network_event)

    # ── Start file system monitor ─────────────────────────────────
    observer = start_monitor(config.WATCH_PATH, engine)
    print(f"\033[32m[*] inotify watcher started on: {config.WATCH_PATH}\033[0m")

    # ── Start network monitor ─────────────────────────────────────
    net_monitor.start()
    print("\033[32m[*] Network monitor started (/proc/net/tcp)\033[0m")

    # ── Graceful shutdown ─────────────────────────────────────────
    def _shutdown(sig, frame):
        observer.stop()
        net_monitor.stop()
        print("\n\033[33m[!] Shutting down...\033[0m")
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    print("\033[32m[*] Launching UI... Press Q to quit\033[0m")
    time.sleep(0.3)

    # ── Launch curses UI ──────────────────────────────────────────
    try:
        curses.wrapper(draw_ui, engine, net_monitor, config.WATCH_PATH)
    finally:
        observer.stop()
        observer.join()
        net_monitor.stop()

    # ── Post-run summary ──────────────────────────────────────────
    stats = logger.get_stats()
    print(f"\n\033[32m{'═'*55}")
    print(f"  RANSOMWARE ANALYZER - SESSION SUMMARY")
    print(f"{'═'*55}")
    print(f"  Final Threat Score : {engine.get_score()}")
    print(f"  Total Events       : {stats['total']}")
    for sev, cnt in stats["by_severity"].items():
        print(f"  {sev:<10}         : {cnt}")
    print(f"  Log file           : {config.LOG_FILE}")
    print(f"{'═'*55}\033[0m\n")


if __name__ == "__main__":
    main()
