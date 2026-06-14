"""
c_bridge.py - Python ↔ C interface via ctypes
Wraps: entropy, proc inspection, process control, network, hash
"""

import ctypes
import os
import sys

# ── Load shared library ──────────────────────────────────────────
_lib_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "entropy_calc.so")

try:
    _lib = ctypes.CDLL(_lib_path)
except OSError as e:
    print(f"[FATAL] Cannot load entropy_calc.so: {e}", file=sys.stderr)
    print(f"[FATAL] Run: gcc -O2 -shared -fPIC -o entropy_calc.so entropy_calc.c -lm", file=sys.stderr)
    sys.exit(1)

# ── entropy ──────────────────────────────────────────────────────
_lib.file_entropy.argtypes     = [ctypes.c_char_p]
_lib.file_entropy.restype      = ctypes.c_double

_lib.calculate_entropy.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
_lib.calculate_entropy.restype  = ctypes.c_double

# ── byte distribution ────────────────────────────────────────────
_lib.file_byte_distribution.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_double)]
_lib.file_byte_distribution.restype  = ctypes.c_long

# ── proc info ────────────────────────────────────────────────────
class _CProcInfo(ctypes.Structure):
    _fields_ = [
        ("pid",       ctypes.c_int),
        ("comm",      ctypes.c_char * 64),
        ("exe",       ctypes.c_char * 256),
        ("state",     ctypes.c_char),
        ("fd_count",  ctypes.c_long),
        ("vm_rss_kb", ctypes.c_long),
    ]

_lib.get_proc_info.argtypes   = [ctypes.c_int, ctypes.POINTER(_CProcInfo)]
_lib.get_proc_info.restype    = ctypes.c_int

_lib.find_pid_for_file.argtypes = [ctypes.c_char_p]
_lib.find_pid_for_file.restype  = ctypes.c_int

# ── process control ───────────────────────────────────────────────
_lib.kill_process.argtypes    = [ctypes.c_int]
_lib.kill_process.restype     = ctypes.c_int

_lib.suspend_process.argtypes = [ctypes.c_int]
_lib.suspend_process.restype  = ctypes.c_int

_lib.resume_process.argtypes  = [ctypes.c_int]
_lib.resume_process.restype   = ctypes.c_int

# ── hash ─────────────────────────────────────────────────────────
_lib.fnv1a_file.argtypes = [ctypes.c_char_p]
_lib.fnv1a_file.restype  = ctypes.c_uint64

# ── tcp connections ───────────────────────────────────────────────
class _CTcpConn(ctypes.Structure):
    _fields_ = [
        ("local_addr",  ctypes.c_uint32),
        ("local_port",  ctypes.c_uint16),
        ("remote_addr", ctypes.c_uint32),
        ("remote_port", ctypes.c_uint16),
        ("state",       ctypes.c_int),
        ("inode",       ctypes.c_uint32),
    ]

_MAX_CONNS = 4096
_lib.read_tcp_connections.argtypes = [ctypes.POINTER(_CTcpConn), ctypes.c_int]
_lib.read_tcp_connections.restype  = ctypes.c_int


# ════════════════════════════════════════════════════════════════
# PUBLIC API
# ════════════════════════════════════════════════════════════════

def file_entropy(filepath: str) -> float:
    """Shannon entropy of a file (0.0–8.0). Returns 0.0 on error."""
    try:
        v = _lib.file_entropy(filepath.encode())
        return max(0.0, v)
    except Exception:
        return 0.0


def buffer_entropy(data: bytes) -> float:
    """Shannon entropy of a bytes buffer."""
    if not data:
        return 0.0
    return _lib.calculate_entropy(data, len(data))


def file_byte_distribution(filepath: str) -> list[float]:
    """Returns list of 256 normalized byte frequencies for a file."""
    arr = (ctypes.c_double * 256)()
    ret = _lib.file_byte_distribution(filepath.encode(), arr)
    if ret <= 0:
        return [0.0] * 256
    return list(arr)


def get_proc_info(pid: int) -> dict | None:
    """Read process metadata from /proc/<pid>."""
    info = _CProcInfo()
    ret  = _lib.get_proc_info(pid, ctypes.byref(info))
    if ret < 0:
        return None
    return {
        "pid":       info.pid,
        "comm":      info.comm.decode(errors="replace"),
        "exe":       info.exe.decode(errors="replace"),
        "state":     info.state.decode(errors="replace"),
        "fd_count":  info.fd_count,
        "vm_rss_kb": info.vm_rss_kb,
    }


def find_pid_for_file(filepath: str) -> int:
    """
    Scan /proc/*/fd to find PID with filepath open.
    Returns PID or -1. Can be slow — use on ALERT events only.
    """
    return _lib.find_pid_for_file(filepath.encode())


def kill_process(pid: int) -> bool:
    """Send SIGKILL to pid. Returns True on success."""
    return _lib.kill_process(pid) == 0


def suspend_process(pid: int) -> bool:
    """Send SIGSTOP to pid."""
    return _lib.suspend_process(pid) == 0


def resume_process(pid: int) -> bool:
    """Send SIGCONT to pid."""
    return _lib.resume_process(pid) == 0


def fnv1a_file(filepath: str) -> int:
    """Fast FNV-1a 64-bit hash of a file for quick allow-list checks."""
    return _lib.fnv1a_file(filepath.encode())


def read_tcp_connections() -> list[dict]:
    """
    Read current TCP connections from /proc/net/tcp.
    Returns list of dicts with addr/port/state/inode.
    """
    buf = (_CTcpConn * _MAX_CONNS)()
    n   = _lib.read_tcp_connections(buf, _MAX_CONNS)
    if n < 0:
        return []

    result = []
    for i in range(n):
        c = buf[i]
        # /proc/net/tcp stores addresses in little-endian hex
        la = c.local_addr
        ra = c.remote_addr
        result.append({
            "local_ip":   f"{la & 0xFF}.{(la>>8)&0xFF}.{(la>>16)&0xFF}.{(la>>24)&0xFF}",
            "local_port":  c.local_port,
            "remote_ip":  f"{ra & 0xFF}.{(ra>>8)&0xFF}.{(ra>>16)&0xFF}.{(ra>>24)&0xFF}",
            "remote_port": c.remote_port,
            "state":       c.state,
            "inode":       c.inode,
        })
    return result
