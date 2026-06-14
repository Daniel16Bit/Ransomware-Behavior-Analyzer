# ╔══════════════════════════════════════════════════════════════╗
# ║         RANSOMWARE ANALYZER - CONFIGURATION                  ║
# ╚══════════════════════════════════════════════════════════════╝

import os

# ── Paths ────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
WATCH_PATH = "/tmp/test_watch"          # Directory to monitor
LOG_DIR    = os.path.join(BASE_DIR, "logs")
HASH_DIR   = os.path.join(BASE_DIR, "hashes")
LOG_FILE   = os.path.join(LOG_DIR, "events.jsonl")
HASH_FILE  = os.path.join(HASH_DIR, "allowlist.sha256")

# ── Entropy thresholds ───────────────────────────────────────────
ENTROPY_THRESHOLD_WARN  = 6.8   # Suspicious (warn)
ENTROPY_THRESHOLD_ALERT = 7.2   # High entropy (alert)
ENTROPY_SAMPLE_MIN_SIZE = 512   # Skip tiny files (bytes)

# ── Behavioral thresholds ────────────────────────────────────────
BURST_WINDOW_SECONDS    = 10    # Sliding window for burst detection
WRITE_BURST_THRESHOLD   = 15    # Writes within window = ALERT
RENAME_THRESHOLD        = 5     # Renames within window = ALERT
DELETE_THRESHOLD        = 10    # Deletes within window = ALERT
UNIQUE_EXT_THRESHOLD    = 3     # New unique extensions created = WARN

# ── Auto-response ────────────────────────────────────────────────
AUTO_KILL_ENABLED       = False  # Kill process when score >= threshold
AUTO_KILL_SCORE         = 85     # Score threshold for auto-kill
AUTO_SUSPEND_SCORE      = 70     # Score threshold for SIGSTOP
SUSPEND_ENABLED         = False  # Suspend (SIGSTOP) before kill

# ── Network monitoring ───────────────────────────────────────────
NET_MONITOR_ENABLED     = True
NET_POLL_INTERVAL       = 2.0   # seconds between /proc/net/tcp polls
# Known C2 / suspicious ports (ransomware families)
SUSPICIOUS_PORTS        = {
    4444, 5555, 6666, 7777, 8888,   # Generic reverse shells
    1194, 1723,                      # VPN tunneling
    9001, 9030,                      # Tor
    4460, 8443, 8080,                # Common C2
    6697, 6667,                      # IRC botnet
}
# Private IP ranges — outbound connections outside these = suspicious
PRIVATE_RANGES = [
    (0x0A000000, 0xFF000000),   # 10.0.0.0/8
    (0xAC100000, 0xFFF00000),   # 172.16.0.0/12
    (0xC0A80000, 0xFFFF0000),   # 192.168.0.0/16
    (0x7F000000, 0xFF000000),   # 127.0.0.0/8
]

# ── Process attribution ──────────────────────────────────────────
PROC_SCAN_ENABLED       = True
PROC_SCAN_ON_ALERT      = True   # Scan /proc when alert triggers
HIGH_FD_COUNT_THRESHOLD = 100    # Many open FDs = suspicious

# ── Known ransomware file extensions ────────────────────────────
RANSOMWARE_EXTENSIONS = {
    # Generic
    '.locked', '.crypto', '.enc', '.encrypted', '.crypt', '.crypted',
    '.lock', '.locky', '.encrypt',
    # Named families
    '.pays', '.ryk', '.ryuk',
    '.conti',
    '.lockbit', '.lb2',
    '.blackcat', '.alphv',
    '.hive',
    '.darkside',
    '.revil', '.sodinokibi',
    '.maze',
    '.dharma', '.phobos',
    '.stop', '.djvu',
    '.cerber',
    '.wannacry', '.wcry', '.wncry', '.wncryt',
    '.petya', '.notpetya',
    '.zepto', '.thor',
    '.aesir', '.odin', '.shit',
    '.wallet', '.globe',
    '.crab', '.gandcrab',
    '.snake', '.ekans',
}

# ── Ransom note filename patterns (uppercase match) ──────────────
RANSOM_NOTE_PATTERNS = [
    'READ_ME', 'README', 'DECRYPT', 'RESTORE_FILE',
    'HOW_TO', 'YOUR_FILES', 'RANSOM', 'HELP_DECRYPT',
    'RECOVER', 'UNLOCK', 'INSTRUCTION', 'PAYMENT',
    'ATTENTION', 'FILES_ENCRYPTED', 'IMPORTANT',
]

# ── Score weights per event type ─────────────────────────────────
SCORE_WEIGHTS = {
    'WRITE_BURST':          10,
    'RENAME_BURST':         15,
    'DELETE_BURST':         15,
    'HIGH_ENTROPY':         20,
    'ENTROPY_WARN':          8,
    'RANSOM_EXTENSION':     40,
    'RENAME_TO_RANSOM_EXT': 35,
    'RANSOM_NOTE':          45,
    'SUSPICIOUS_NETWORK':   25,
    'SUSPICIOUS_PORT':      20,
    'EXTERNAL_CONNECT':     15,
    'PROCESS_KILLED':        0,
    'PROCESS_SUSPENDED':     0,
    'HIGH_FD_COUNT':        10,
    'NEW_UNIQUE_EXTENSIONS': 8,
}

# ── UI settings ──────────────────────────────────────────────────
UI_REFRESH_HZ      = 4     # Redraws per second
UI_MAX_EVENTS      = 500   # Keep in memory
UI_LOG_PANEL_RATIO = 0.55  # Fraction of screen for event log
