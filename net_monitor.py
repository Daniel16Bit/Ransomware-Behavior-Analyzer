"""
net_monitor.py - Network connection monitor via /proc/net/tcp
No root required! Polls /proc/net/tcp and /proc/net/tcp6 periodically.
Detects: new external connections, suspicious ports, C2 indicators.
Linux-only.
"""

import time
import threading
import socket
import struct
import os
from collections import defaultdict
from typing import Optional

import config
import logger
from c_bridge import read_tcp_connections

# ── TCP state names ───────────────────────────────────────────────
TCP_STATE = {
    1: "ESTABLISHED", 2: "SYN_SENT",  3: "SYN_RECV",
    4: "FIN_WAIT1",   5: "FIN_WAIT2", 6: "TIME_WAIT",
    7: "CLOSE",       8: "CLOSE_WAIT",9: "LAST_ACK",
    10: "LISTEN",     11: "CLOSING",
}


def _is_private_ip(ip_str: str) -> bool:
    """Check if IP is in a private/loopback range."""
    if ip_str in ("0.0.0.0", "127.0.0.1", "::1", ""):
        return True
    try:
        packed = struct.unpack("!I", socket.inet_aton(ip_str))[0]
    except OSError:
        return True
    for (net, mask) in config.PRIVATE_RANGES:
        if (packed & mask) == net:
            return True
    return False


def _inode_to_pid(inode: int) -> Optional[int]:
    """
    Map a socket inode to a PID by scanning /proc/<pid>/fd.
    Returns PID or None.
    """
    target = f"socket:[{inode}]"
    try:
        for entry in os.scandir("/proc"):
            if not entry.name.isdigit():
                continue
            fd_dir = f"/proc/{entry.name}/fd"
            try:
                for fd in os.scandir(fd_dir):
                    try:
                        if os.readlink(fd.path) == target:
                            return int(entry.name)
                    except OSError:
                        pass
            except (OSError, PermissionError):
                pass
    except OSError:
        pass
    return None


class NetworkMonitor:
    def __init__(self, engine_callback=None):
        """
        engine_callback: callable(event_type, details) called on detections.
        """
        self._callback    = engine_callback
        self._prev_conns  = set()   # frozensets of (local_ip, lport, remote_ip, rport)
        self._running     = False
        self._thread: Optional[threading.Thread] = None

        # Connection frequency tracking (remote_ip -> [timestamps])
        self._conn_times  = defaultdict(list)

    def start(self):
        if not config.NET_MONITOR_ENABLED:
            return
        self._running = True
        self._thread  = threading.Thread(
            target=self._poll_loop, daemon=True, name="NetMonitor"
        )
        self._thread.start()

    def stop(self):
        self._running = False

    def _poll_loop(self):
        while self._running:
            try:
                self._poll()
            except Exception as e:
                logger.log_event("INFO", "NET_MONITOR_ERROR", "", {"error": str(e)})
            time.sleep(config.NET_POLL_INTERVAL)

    def _poll(self):
        conns = read_tcp_connections()
        now   = time.time()

        current_keys = set()
        for c in conns:
            key = (c["local_ip"], c["local_port"], c["remote_ip"], c["remote_port"])
            current_keys.add(key)

            # Only care about ESTABLISHED outbound connections
            if c["state"] != 1:  # 1 = ESTABLISHED
                continue
            if c["remote_ip"] in ("0.0.0.0", ""):
                continue

            # ── New connection detected ───────────────────────────
            if key not in self._prev_conns:
                self._on_new_connection(c, now)

        self._prev_conns = current_keys

        # ── Cleanup old tracking data ─────────────────────────────
        cutoff = now - 60
        for ip in list(self._conn_times.keys()):
            self._conn_times[ip] = [t for t in self._conn_times[ip] if t > cutoff]
            if not self._conn_times[ip]:
                del self._conn_times[ip]

    def _on_new_connection(self, conn: dict, now: float):
        remote_ip   = conn["remote_ip"]
        remote_port = conn["remote_port"]
        local_port  = conn["local_port"]

        details = {
            "remote_ip":   remote_ip,
            "remote_port": remote_port,
            "local_port":  local_port,
            "state":       TCP_STATE.get(conn["state"], "UNKNOWN"),
        }

        # Try to attribute to a PID
        pid = _inode_to_pid(conn["inode"])
        if pid:
            details["pid"] = pid
            try:
                with open(f"/proc/{pid}/comm") as f:
                    details["proc"] = f.read().strip()
            except OSError:
                pass

        fired = False

        # ── Check: Suspicious port ────────────────────────────────
        if remote_port in config.SUSPICIOUS_PORTS or local_port in config.SUSPICIOUS_PORTS:
            logger.log_event(
                "ALERT", "SUSPICIOUS_PORT",
                f"{remote_ip}:{remote_port}",
                {**details, "reason": "known_c2_or_shell_port"},
                pid=pid,
            )
            if self._callback:
                self._callback("SUSPICIOUS_PORT", details)
            fired = True

        # ── Check: External (non-private) IP ─────────────────────
        if not _is_private_ip(remote_ip):
            self._conn_times[remote_ip].append(now)

            logger.log_event(
                "WARN", "EXTERNAL_CONNECT",
                f"{remote_ip}:{remote_port}",
                details,
                pid=pid,
            )
            if self._callback and not fired:
                self._callback("EXTERNAL_CONNECT", details)

            # Burst of connections to same external IP?
            recent = self._conn_times[remote_ip]
            if len(recent) >= 5:
                logger.log_event(
                    "ALERT", "CONNECTION_BURST",
                    remote_ip,
                    {**details, "conn_count_60s": len(recent)},
                    pid=pid,
                )
                if self._callback:
                    self._callback("CONNECTION_BURST", details)

    def get_active_connections(self) -> list[dict]:
        """Return currently ESTABLISHED connections (for UI display)."""
        conns = read_tcp_connections()
        return [c for c in conns if c["state"] == 1
                and c["remote_ip"] not in ("0.0.0.0", "")]
