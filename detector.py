"""
detector.py - Behavioral Detection Engine
Combines: entropy, extension detection, burst analysis,
process attribution, allowlist checks, auto-kill/suspend.
"""

import os
import time
import threading
from collections import defaultdict, deque
from typing import Optional

import config
import logger
import allowlist
import proc_monitor
from c_bridge import file_entropy, get_proc_info, kill_process, suspend_process


class BehaviorEngine:
    def __init__(self):
        self._lock        = threading.Lock()

        # Sliding-window event trackers
        self._write_times  = defaultdict(lambda: deque(maxlen=200))
        self._rename_times = deque(maxlen=200)
        self._delete_times = deque(maxlen=200)

        # Extension tracking (unique new extensions seen)
        self._new_extensions: set = set()

        # Score
        self.threat_score  = 0
        self.score_history = deque(maxlen=300)   # (timestamp, score)

        # Killed/suspended PIDs (avoid double-action)
        self._actioned_pids: set = set()

        # Callbacks for UI
        self.on_alert = None   # callable(event_dict)

    # ════════════════════════════════════════════════════════════
    # FILE SYSTEM EVENT HANDLERS
    # ════════════════════════════════════════════════════════════

    def on_modified(self, filepath: str):
        now = time.time()
        with self._lock:
            self._write_times[filepath].append(now)
            recent_writes = sum(
                1 for t in self._write_times[filepath]
                if now - t < config.BURST_WINDOW_SECONDS
            )

        # Write burst?
        if recent_writes >= config.WRITE_BURST_THRESHOLD:
            self._raise(
                "ALERT", "WRITE_BURST", filepath,
                {"count": recent_writes, "window_sec": config.BURST_WINDOW_SECONDS}
            )

        # Entropy check (skip tiny files)
        if os.path.isfile(filepath):
            try:
                size = os.path.getsize(filepath)
                if size >= config.ENTROPY_SAMPLE_MIN_SIZE:
                    entropy = file_entropy(filepath)
                    if entropy >= config.ENTROPY_THRESHOLD_ALERT:
                        self._raise(
                            "ALERT", "HIGH_ENTROPY", filepath,
                            {"entropy": round(entropy, 4), "size": size}
                        )
                    elif entropy >= config.ENTROPY_THRESHOLD_WARN:
                        self._raise(
                            "WARN", "ENTROPY_WARN", filepath,
                            {"entropy": round(entropy, 4), "size": size}
                        )
            except OSError:
                pass

    def on_created(self, filepath: str):
        name = os.path.basename(filepath).upper()
        ext  = os.path.splitext(filepath)[1].lower()

        # Ransomware extension?
        if ext in config.RANSOMWARE_EXTENSIONS:
            self._raise(
                "CRITICAL", "RANSOM_EXTENSION", filepath,
                {"extension": ext}
            )

        # Ransom note?
        if any(p in name for p in config.RANSOM_NOTE_PATTERNS):
            self._raise(
                "CRITICAL", "RANSOM_NOTE", filepath,
                {"filename": os.path.basename(filepath)}
            )

        # Track new unique extensions
        if ext and ext not in ('.tmp', '.bak', '.log', ''):
            with self._lock:
                if ext not in self._new_extensions:
                    self._new_extensions.add(ext)
                    n_ext = len(self._new_extensions)

            if n_ext >= config.UNIQUE_EXT_THRESHOLD:
                self._raise(
                    "WARN", "NEW_UNIQUE_EXTENSIONS", filepath,
                    {"count": n_ext, "extensions": list(self._new_extensions)[-10:]}
                )

    def on_deleted(self, filepath: str):
        now = time.time()
        with self._lock:
            self._delete_times.append(now)
            recent_deletes = sum(
                1 for t in self._delete_times
                if now - t < config.BURST_WINDOW_SECONDS
            )

        if recent_deletes >= config.DELETE_THRESHOLD:
            self._raise(
                "ALERT", "DELETE_BURST", filepath,
                {"count": recent_deletes, "window_sec": config.BURST_WINDOW_SECONDS}
            )

    def on_renamed(self, src: str, dst: str):
        now = time.time()
        with self._lock:
            self._rename_times.append(now)
            recent_renames = sum(
                1 for t in self._rename_times
                if now - t < config.BURST_WINDOW_SECONDS
            )

        dst_ext = os.path.splitext(dst)[1].lower()

        # Rename TO ransomware extension?
        if dst_ext in config.RANSOMWARE_EXTENSIONS:
            self._raise(
                "CRITICAL", "RENAME_TO_RANSOM_EXT", dst,
                {"from": src, "to": dst, "extension": dst_ext}
            )

        # Rename burst?
        if recent_renames >= config.RENAME_THRESHOLD:
            self._raise(
                "ALERT", "RENAME_BURST", dst,
                {"count": recent_renames, "window_sec": config.BURST_WINDOW_SECONDS}
            )

    def on_network_event(self, event_type: str, details: dict):
        """Called by NetworkMonitor on suspicious connections."""
        score = config.SCORE_WEIGHTS.get(event_type, 10)
        with self._lock:
            self.threat_score = min(100, self.threat_score + score)
            self.score_history.append((time.time(), self.threat_score))

    # ════════════════════════════════════════════════════════════
    # INTERNAL
    # ════════════════════════════════════════════════════════════

    def _raise(
        self,
        severity:   str,
        event_type: str,
        filepath:   str,
        details:    dict,
    ):
        # ── Process attribution ───────────────────────────────────
        pid       = None
        proc_info = None
        if config.PROC_SCAN_ON_ALERT and severity in ("ALERT", "CRITICAL"):
            proc_info = proc_monitor.attribute_file_event(filepath)
            if proc_info:
                pid = proc_info.get("pid")

        # ── Allowlist check ───────────────────────────────────────
        if pid and allowlist.is_allowed_pid(pid):
            return   # Trusted process — skip

        # ── Score update ──────────────────────────────────────────
        weight = config.SCORE_WEIGHTS.get(event_type, 5)
        with self._lock:
            self.threat_score = min(100, self.threat_score + weight)
            self.score_history.append((time.time(), self.threat_score))
            score_now = self.threat_score

        # ── Log ───────────────────────────────────────────────────
        entry = logger.log_event(
            severity, event_type, filepath, details,
            pid=pid, proc_info=proc_info
        )

        # ── Notify UI ─────────────────────────────────────────────
        if self.on_alert:
            try:
                self.on_alert(entry)
            except Exception:
                pass

        # ── Auto-response ─────────────────────────────────────────
        if pid and pid not in self._actioned_pids:
            self._auto_respond(pid, score_now, filepath)

    def _auto_respond(self, pid: int, score: int, filepath: str):
        """Apply auto-kill or auto-suspend based on threat score."""
        if score >= config.AUTO_KILL_SCORE and config.AUTO_KILL_ENABLED:
            if kill_process(pid):
                with self._lock:
                    self._actioned_pids.add(pid)
                logger.log_event(
                    "CRITICAL", "PROCESS_KILLED", filepath,
                    {"pid": pid, "score": score, "action": "SIGKILL"}
                )
        elif score >= config.AUTO_SUSPEND_SCORE and config.SUSPEND_ENABLED:
            if pid not in self._actioned_pids:
                if suspend_process(pid):
                    with self._lock:
                        self._actioned_pids.add(pid)
                    logger.log_event(
                        "ALERT", "PROCESS_SUSPENDED", filepath,
                        {"pid": pid, "score": score, "action": "SIGSTOP"}
                    )

    # ════════════════════════════════════════════════════════════
    # PUBLIC ACCESSORS (thread-safe, for UI)
    # ════════════════════════════════════════════════════════════

    def get_score(self) -> int:
        with self._lock:
            return self.threat_score

    def reset_score(self):
        with self._lock:
            self.threat_score = 0
            self.score_history.clear()

    def get_score_history(self) -> list[tuple]:
        with self._lock:
            return list(self.score_history)
