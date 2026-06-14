# 🔴 RANSOMWARE BEHAVIOR ANALYZER v2.0
## Linux-only | Python + C | ASCII Terminal UI

```
██████╗  █████╗ ███╗  ██╗███████╗ ██████╗ ███╗  ███╗
██╔══██╗██╔══██╗████╗ ██║██╔════╝██╔═══██╗████╗████║
██████╔╝███████║██╔██╗██║███████╗██║   ██║██╔████╔██║
██╔══██╗██╔══██║██║╚████║╚════██║██║   ██║██║╚██╔╝██║
██║  ██║██║  ██║██║ ╚███║███████║╚██████╔╝██║ ╚═╝ ██║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝
         [ BEHAVIORAL RANSOMWARE ANALYZER v2.0 ]
```

---

## Architecture

```
ransomware-analyzer/
├── entropy_calc.c      # C: entropy, inode scan, proc info, tcp reader
├── entropy_calc.so     # Compiled shared library (gcc)
├── c_bridge.py         # Python ↔ C ctypes bridge
├── config.py           # All thresholds and settings
├── logger.py           # Structured JSONL logger + ring buffer
├── allowlist.py        # SHA-256 process allowlist manager
├── proc_monitor.py     # /proc filesystem process attribution
├── net_monitor.py      # /proc/net/tcp network monitor (no root!)
├── detector.py         # Behavioral detection engine + auto-response
├── monitor.py          # inotify file system watcher (watchdog)
├── main.py             # Curses ASCII UI + orchestration
├── run.sh              # Build, run, test helper
└── logs/events.jsonl   # Structured event log (JSONL)
```

---

## Quick Start

```bash
# Terminal 1 — Run analyzer
./run.sh run

# Terminal 2 — Simulate ransomware behavior
./run.sh test
```

---

## Features

### 🔬 Entropy Analysis (C module)
- Shannon entropy calculated in C for maximum performance
- Samples up to 512KB per file
- Byte frequency distribution (256 buckets) for visualization
- Thresholds: **WARN** ≥ 6.8 bits, **ALERT** ≥ 7.2 bits (max = 8.0)

### 👁 File System Monitor (inotify via watchdog)
- Real-time via Linux `inotify` syscall
- Events: `MODIFY`, `CREATE`, `DELETE`, `RENAME/MOVE`
- Recursive directory watching

### 🧠 Behavioral Detection Engine
| Detection          | Trigger                                      | Severity |
|--------------------|----------------------------------------------|----------|
| `WRITE_BURST`      | ≥15 writes to same file in 10s               | ALERT    |
| `RENAME_BURST`     | ≥5 renames in 10s                            | ALERT    |
| `DELETE_BURST`     | ≥10 deletes in 10s                           | ALERT    |
| `HIGH_ENTROPY`     | File entropy ≥ 7.2 bits                      | ALERT    |
| `ENTROPY_WARN`     | File entropy ≥ 6.8 bits                      | WARN     |
| `RANSOM_EXTENSION` | Known ransomware extension created           | CRITICAL |
| `RENAME_TO_RANSOM_EXT` | File renamed to ransomware extension   | CRITICAL |
| `RANSOM_NOTE`      | Ransom note filename pattern detected        | CRITICAL |
| `DELETE_BURST`     | Mass deletion                                | ALERT    |
| `NEW_UNIQUE_EXT`   | Many unique new extensions created           | WARN     |

### 🌐 Network Monitor (/proc/net/tcp — **no root required!**)
| Detection            | Trigger                              | Severity |
|----------------------|--------------------------------------|----------|
| `SUSPICIOUS_PORT`    | Connection to known C2/shell ports   | ALERT    |
| `EXTERNAL_CONNECT`   | Outbound non-private IP connection   | WARN     |
| `CONNECTION_BURST`   | ≥5 connections to same IP in 60s     | ALERT    |

Suspicious ports include: 4444, 5555, 6666, 7777, 8888, 9001 (Tor), 6667 (IRC), 8443...

### 🔍 Process Attribution (/proc filesystem)
- Maps file events to PIDs via `/proc/<pid>/fd` scanning
- Reads: comm, exe, state, FD count, RSS memory
- Detects high FD count (≥100 = suspicious — encryption activity)
- No ptrace or root required!

### 🔐 SHA-256 Allowlist
- Hash-based allowlist for trusted processes
- Pre-seeds with common system tools
- Auto-skips alerts from allowed PIDs
- Persistent: stored in `hashes/allowlist.sha256`

### ⚡ Auto-Response (disabled by default)
- **SIGSTOP** (suspend): When score ≥ 70 and `SUSPEND_ENABLED=True`
- **SIGKILL** (terminate): When score ≥ 85 and `AUTO_KILL_ENABLED=True`
- Toggle from UI: `[S]` for suspend, `[K]` for kill

---

## UI Controls

| Key   | Action                        |
|-------|-------------------------------|
| `Q`   | Quit                          |
| `R`   | Reset threat score + clear UI |
| `TAB` | Switch panels                 |
| `↑↓`  | Scroll event log              |
| `K`   | Toggle auto-kill mode         |
| `S`   | Toggle auto-suspend mode      |
| `A`   | Dump allowlist to log         |

### Panels
1. **EVENTS** — Real-time event log with severity coloring
2. **NETWORK** — Active TCP connections (from /proc/net/tcp)
3. **PROCESSES** — Top processes by file descriptor count

---

## Configuration (`config.py`)

```python
WATCH_PATH              = "/tmp/test_watch"   # Directory to monitor
ENTROPY_THRESHOLD_ALERT = 7.2                 # Bits (max 8.0)
BURST_WINDOW_SECONDS    = 10                  # Detection window
WRITE_BURST_THRESHOLD   = 15                  # Writes/window
AUTO_KILL_ENABLED       = False               # DANGEROUS — enable carefully
AUTO_KILL_SCORE         = 85                  # Score trigger for SIGKILL
```

---

## Python/C Split Rationale

| Task                         | Language | Why                              |
|------------------------------|----------|----------------------------------|
| Shannon entropy calculation  | **C**    | O(n) over file bytes, microseconds |
| /proc/fd inode scanning      | **C**    | Many readlink() calls, fast loop |
| Byte frequency distribution  | **C**    | 256-bucket array, tight loop     |
| TCP connection parsing       | **C**    | sscanf over /proc/net/tcp lines  |
| Behavioral logic             | Python   | Complex rules, easy to change    |
| curses UI                    | Python   | High-level terminal control      |
| inotify orchestration        | Python   | watchdog library                 |
| SHA-256 allowlist            | Python   | hashlib, sufficient speed        |

---

## Log Format (JSONL)

```json
{
  "ts":       "2025-01-15T14:32:01.234567+00:00",
  "severity": "CRITICAL",
  "event":    "RANSOM_EXTENSION",
  "file":     "/tmp/test_watch/document.locked",
  "details":  {"extension": ".locked"},
  "pid":      12345,
  "proc":     {"comm": "python3", "exe": "/usr/bin/python3", "fd_count": 23}
}
```

---

## Requirements

- **OS**: Linux (kernel ≥ 3.5 for inotify_init1, /proc/net/tcp)
- **GCC**: any modern version
- **Python**: 3.10+
- **pip**: `watchdog` (psutil optional for enhanced proc panel)

```bash
pip install watchdog psutil
gcc -O2 -shared -fPIC -o entropy_calc.so entropy_calc.c -lm
```

---

## Known Ransomware Extensions Detected (100+)

`.locked`, `.crypto`, `.enc`, `.encrypted`, `.ryuk`, `.conti`, `.lockbit`,
`.blackcat`, `.alphv`, `.hive`, `.darkside`, `.revil`, `.maze`, `.dharma`,
`.phobos`, `.stop`, `.djvu`, `.cerber`, `.wannacry`, `.wcry`, `.petya`,
`.notpetya`, `.zepto`, `.wallet`, `.gandcrab`, `.snake`, `.ekans`, and more...
