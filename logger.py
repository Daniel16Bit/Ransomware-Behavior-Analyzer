"""
logger.py - Structured JSONL event logger + in-memory ring buffer for UI
"""

import json
import os
import threading
from datetime import datetime, timezone
from collections import deque

import config

# ── Setup ────────────────────────────────────────────────────────
os.makedirs(config.LOG_DIR, exist_ok=True)

_lock         = threading.Lock()
_event_buffer = deque(maxlen=config.UI_MAX_EVENTS)
_stats        = {
    "total": 0,
    "by_severity": {"INFO": 0, "WARN": 0, "ALERT": 0, "CRITICAL": 0},
    "by_event":    {},
}

# ── TCP states (Linux /proc/net/tcp numeric codes) ────────────────
TCP_STATES = {
    1: "ESTABLISHED", 2: "SYN_SENT",  3: "SYN_RECV",
    4: "FIN_WAIT1",   5: "FIN_WAIT2", 6: "TIME_WAIT",
    7: "CLOSE",       8: "CLOSE_WAIT",9: "LAST_ACK",
    10: "LISTEN",     11: "CLOSING",
}


def log_event(
    severity:   str,
    event_type: str,
    filepath:   str,
    details:    dict = None,
    pid:        int  = None,
    proc_info:  dict = None,
) -> dict:
    """
    Log a structured event.

    severity  : INFO | WARN | ALERT | CRITICAL
    event_type: machine-readable tag (e.g. HIGH_ENTROPY)
    filepath  : affected file/path
    details   : arbitrary extra data
    pid       : attributed process ID (optional)
    proc_info : dict from c_bridge.get_proc_info (optional)
    """
    entry = {
        "ts":       datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "event":    event_type,
        "file":     filepath,
        "details":  details or {},
    }
    if pid is not None:
        entry["pid"] = pid
    if proc_info:
        entry["proc"] = proc_info

    with _lock:
        # Write to JSONL log
        with open(config.LOG_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # Update ring buffer + stats
        _event_buffer.append(entry)
        _stats["total"] += 1
        _stats["by_severity"][severity] = _stats["by_severity"].get(severity, 0) + 1
        _stats["by_event"][event_type]  = _stats["by_event"].get(event_type, 0) + 1

    return entry


def get_events(n: int = 50) -> list:
    """Return last n events (thread-safe)."""
    with _lock:
        events = list(_event_buffer)
    return events[-n:]


def get_stats() -> dict:
    with _lock:
        return dict(_stats)


def clear_events():
    with _lock:
        _event_buffer.clear()
