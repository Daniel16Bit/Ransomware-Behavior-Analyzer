"""
monitor.py - File system monitor
Uses watchdog (Linux backend: inotify) to watch directory trees.
"""

import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from detector import BehaviorEngine
import config


class _RansomwareHandler(FileSystemEventHandler):
    def __init__(self, engine: BehaviorEngine):
        super().__init__()
        self.engine = engine

    def on_modified(self, event):
        if not event.is_directory:
            self.engine.on_modified(event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.engine.on_created(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.engine.on_deleted(event.src_path)

    def on_moved(self, event):
        # watchdog "moved" = rename/move
        self.engine.on_renamed(event.src_path, event.dest_path)


def start_monitor(watch_path: str, engine: BehaviorEngine) -> Observer:
    """Start inotify-backed file system monitor. Returns the Observer."""
    os.makedirs(watch_path, exist_ok=True)
    handler  = _RansomwareHandler(engine)
    observer = Observer()
    observer.schedule(handler, watch_path, recursive=True)
    observer.start()
    return observer
