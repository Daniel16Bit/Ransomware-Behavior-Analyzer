"""
allowlist.py - SHA-256 based process / file allowlist
Uses Python hashlib for SHA-256, C FNV-1a for fast pre-filter
"""

import hashlib
import os
import json
import threading

import config
import logger

_lock      = threading.Lock()
_allowlist: dict[str, str] = {}   # sha256_hex -> label
_loaded    = False


def _sha256_file(filepath: str) -> str | None:
    """Compute SHA-256 of a file. Returns hex string or None on error."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _load():
    global _loaded
    if os.path.exists(config.HASH_FILE):
        try:
            with open(config.HASH_FILE) as f:
                data = json.load(f)
            with _lock:
                _allowlist.update(data)
        except Exception:
            pass
    _loaded = True


def _save():
    os.makedirs(config.HASH_DIR, exist_ok=True)
    with open(config.HASH_FILE, "w") as f:
        json.dump(_allowlist, f, indent=2)


def load():
    _load()


def add_process(exe_path: str, label: str = "") -> str | None:
    """Hash a process executable and add it to the allowlist."""
    if not _loaded:
        _load()
    sha = _sha256_file(exe_path)
    if sha is None:
        return None
    with _lock:
        _allowlist[sha] = label or exe_path
        _save()
    logger.log_event("INFO", "ALLOWLIST_ADD", exe_path, {"sha256": sha, "label": label})
    return sha


def remove(sha256: str):
    with _lock:
        _allowlist.pop(sha256, None)
        _save()


def is_allowed_pid(pid: int) -> bool:
    """Check if the process exe for pid is in the allowlist."""
    if not _loaded:
        _load()
    exe_path = f"/proc/{pid}/exe"
    try:
        real_exe = os.readlink(exe_path)
    except OSError:
        return False
    sha = _sha256_file(real_exe)
    if sha is None:
        return False
    with _lock:
        return sha in _allowlist


def is_allowed_file(filepath: str) -> bool:
    """Check if a file's SHA-256 is in the allowlist."""
    if not _loaded:
        _load()
    sha = _sha256_file(filepath)
    if sha is None:
        return False
    with _lock:
        return sha in _allowlist


def get_all() -> dict:
    if not _loaded:
        _load()
    with _lock:
        return dict(_allowlist)


def seed_system_processes():
    """
    Seed the allowlist with common system process executables.
    Call once on first run to avoid false positives from system tools.
    """
    common = [
        "/usr/bin/python3", "/usr/bin/python",
        "/bin/bash", "/usr/bin/bash",
        "/bin/sh", "/usr/bin/sh",
        "/usr/bin/cp", "/usr/bin/mv",
        "/usr/bin/rsync", "/usr/bin/tar",
        "/usr/bin/zip", "/usr/bin/gzip",
    ]
    added = 0
    for path in common:
        if os.path.exists(path):
            add_process(path, f"system:{os.path.basename(path)}")
            added += 1
    return added
