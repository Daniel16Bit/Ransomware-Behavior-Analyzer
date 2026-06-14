"""
proc_monitor.py - Process attribution via /proc filesystem
Links file system events to processes. Linux-only.
"""

import os
import re
import time
import threading
from collections import defaultdict
from typing import Optional

import config
import logger
import allowlist
from c_bridge import get_proc_info, find_pid_for_file


# ── Process cache (pid -> info dict) ─────────────────────────────
_proc_cache: dict[int, dict] = {}
_cache_lock  = threading.Lock()
_cache_ttl   = 5.0   # seconds


def _refresh_proc_cache():
    """Scan /proc for all running PIDs and cache their info."""
    pids = []
    try:
        for entry in os.scandir("/proc"):
            if entry.name.isdigit():
                pids.append(int(entry.name))
    except OSError:
        return

    now = time.time()
    new_cache = {}
    for pid in pids:
        info = get_proc_info(pid)
        if info:
            info["cached_at"] = now
            new_cache[pid] = info

    with _cache_lock:
        _proc_cache.clear()
        _proc_cache.update(new_cache)


def get_all_procs() -> list[dict]:
    """Return all known processes from cache."""
    _refresh_proc_cache()
    with _cache_lock:
        return list(_proc_cache.values())


def get_proc(pid: int) -> Optional[dict]:
    """Get info for a specific PID (fresh from /proc)."""
    return get_proc_info(pid)


def attribute_file_event(filepath: str) -> Optional[dict]:
    """
    Try to find which process is responsible for a file event.
    Uses /proc/<pid>/fd scanning via C bridge.
    Returns proc info dict or None.
    """
    if not config.PROC_SCAN_ENABLED:
        return None

    pid = find_pid_for_file(filepath)
    if pid <= 0:
        return None

    info = get_proc_info(pid)
    if info:
        info["attributed_file"] = filepath
    return info


def scan_suspicious_procs() -> list[dict]:
    """
    Scan all processes for suspicious behavior:
    - Many open FDs (file descriptor exhaustion = encryption activity)
    - Not in allowlist
    - High memory usage
    Returns list of suspicious proc dicts.
    """
    _refresh_proc_cache()
    suspicious = []

    with _cache_lock:
        procs = list(_proc_cache.values())

    for p in procs:
        flags = []

        if p["fd_count"] >= config.HIGH_FD_COUNT_THRESHOLD:
            flags.append(f"high_fd:{p['fd_count']}")

        if flags:
            is_allowed = allowlist.is_allowed_pid(p["pid"])
            if not is_allowed:
                p["suspicious_flags"] = flags
                suspicious.append(p)
                logger.log_event(
                    "WARN", "HIGH_FD_COUNT",
                    p["exe"],
                    {"pid": p["pid"], "comm": p["comm"],
                     "fd_count": p["fd_count"], "flags": flags},
                    pid=p["pid"],
                )

    return suspicious


def get_open_files_for_pid(pid: int) -> list[str]:
    """
    Return list of files currently open by a process.
    Reads /proc/<pid>/fd symlinks.
    """
    fd_dir = f"/proc/{pid}/fd"
    files  = []
    try:
        for entry in os.scandir(fd_dir):
            try:
                target = os.readlink(entry.path)
                if target.startswith("/") and not target.startswith("/proc"):
                    files.append(target)
            except OSError:
                pass
    except (OSError, PermissionError):
        pass
    return files


def get_cmdline(pid: int) -> str:
    """Read command line for a PID from /proc."""
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read(512)
        return raw.replace(b"\x00", b" ").decode(errors="replace").strip()
    except OSError:
        return ""
