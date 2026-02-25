#!usr/bin/env python3

'''
Linux-only
    pip install watchdog psutil
    gcc -02 -shared -fPIC -o entropy_calc.so entropy_calc.c -lm
'''

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
SUBTITLE = "[BEHAVIOR RANSOMWARE ANALYZER V2.0 :: Linux Edition]"

SEV_SYMBOL = {
    "INFO":     ("·",  1),   # cyan
    "WARN":     ("▲",  3),   # yellow
    "ALERT":    ("■",  4),   # red
    "CRITICAL": ("◆",  5),   # magenta+bold
}


# cursos color pain ID's

C_GREEN = 1
C_CYAN = 2
C_YELLOW = 3
C_RED = 4
C_MAGENTA = 5
C_WHITE = 6
C_DGRAY = 7

HELP_TEXT = (
    " [Q]uit [R]eset Score [A]llowList [K]ill mode [S]uspend mode "
    " [TAB]switch panel  [↑↓]scroll "
)

# ════════════════════════════════════════════════════════════════
# HELPER DRAWING FUNCTIONS
# ════════════════════════════════════════════════════════════════

def _safe_addstr(win, y,x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or x >= h or x >= w:
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

def _hline(win, y, x, char, lenght, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h:
        return
    lenght = min(lenght, w - x - 10)
    try:
        win.addstr(y, x, char * lenght, attr)
    except curses.error:
        pass


def _thread_bar(score: int, width: int = 35) -> tuple[str, int]:
    """Returns (bar_string, color_pair)."""
    filled = int((score / 100,) * width)
    bar = "█" * filled +  "░" * (width - filled)
    color = (C_RED if score < 70 else C_YELLOW if score > 40 else C_GREEN)
    return f"[{bar}] {score:3d}%", color

def _score_sparkline(history: list, width: int = 40)-> str:
    """Render a Mini sparkline of score History."""
    SPARKS = " ▁▂▃▄▅▆▇█"
    if not history:
        return "─" * width
    vals = [s for _, s in history]
    # SAMPLE TO FIT WIDTH
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