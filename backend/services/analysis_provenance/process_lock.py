from __future__ import annotations

import os
import threading
import time
from pathlib import Path

if os.name == "nt":
    import msvcrt
else:
    import fcntl


class ProcessSafeRLock:
    """Thread-safe, process-safe re-entrant advisory file lock."""

    def __init__(
        self,
        lock_path: str | Path,
        timeout_seconds: float = 15.0,
    ) -> None:
        self.lock_path = Path(lock_path)
        self.timeout_seconds = float(timeout_seconds)
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._thread_lock = threading.RLock()
        self._owner_thread: int | None = None
        self._depth = 0
        self._handle = None

    def _try_os_lock(self, handle) -> bool:
        if os.name == "nt":
            try:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                return True
            except OSError:
                return False
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except OSError:
            return False

    def _unlock_os(self, handle) -> None:
        if os.name == "nt":
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)

    def acquire(self) -> None:
        self._thread_lock.acquire()
        tid = threading.get_ident()

        if self._owner_thread == tid:
            self._depth += 1
            return

        deadline = time.monotonic() + self.timeout_seconds
        handle = None

        try:
            while True:
                handle = open(self.lock_path, "a+b")

                if os.path.getsize(self.lock_path) == 0:
                    handle.write(b"0")
                    handle.flush()
                    os.fsync(handle.fileno())

                if self._try_os_lock(handle):
                    self._handle = handle
                    self._owner_thread = tid
                    self._depth = 1
                    return

                handle.close()
                handle = None

                if time.monotonic() >= deadline:
                    raise TimeoutError(
                        f"Timed out acquiring process lock: {self.lock_path}"
                    )

                time.sleep(0.05)

        except Exception:
            if handle is not None:
                try:
                    handle.close()
                except Exception:
                    pass
            self._thread_lock.release()
            raise

    def release(self) -> None:
        tid = threading.get_ident()
        if self._owner_thread != tid:
            raise RuntimeError(
                "ProcessSafeRLock released by non-owner thread"
            )

        self._depth -= 1

        if self._depth == 0:
            handle = self._handle
            self._handle = None
            self._owner_thread = None

            if handle is not None:
                try:
                    self._unlock_os(handle)
                finally:
                    handle.close()

        self._thread_lock.release()

    def __enter__(self) -> "ProcessSafeRLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.release()
        return False
