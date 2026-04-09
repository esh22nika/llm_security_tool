"""
SentinelLayer — Structured Logging + Observability Layer
=========================================================
Provides:
  • Severity-tagged, ISO-timestamped runtime log records
  • In-memory ring buffer (configurable max size)
  • Thread-safe writes via threading.Lock
  • /sentinel/logs data provider (consumed by FastAPI endpoint)
  • Severity filter support for log retrieval

Log format:
  [TIMESTAMP] [LEVEL] SOURCE — message

Levels: INFO | WARN | BLOCK | PASS | ERROR
"""

import threading
import datetime
from collections import deque
from dataclasses import dataclass, asdict
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# LOG LEVELS
# ─────────────────────────────────────────────────────────────────────────────

class LogLevel:
    INFO  = "INFO"
    WARN  = "WARN"
    BLOCK = "BLOCK"
    PASS  = "PASS"
    ERROR = "ERROR"

_LEVEL_ORDER = {
    LogLevel.INFO:  0,
    LogLevel.PASS:  1,
    LogLevel.WARN:  2,
    LogLevel.BLOCK: 3,
    LogLevel.ERROR: 4,
}


# ─────────────────────────────────────────────────────────────────────────────
# LOG RECORD
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class LogRecord:
    timestamp: str          # ISO 8601
    level: str              # INFO | WARN | BLOCK | PASS | ERROR
    source: str             # which module/component emitted this
    message: str
    context: Optional[dict] = None   # optional structured metadata

    def to_dict(self) -> dict:
        return asdict(self)

    def __str__(self) -> str:
        ctx = f" | ctx={self.context}" if self.context else ""
        return f"[{self.timestamp}] [{self.level:>5}] {self.source} — {self.message}{ctx}"


# ─────────────────────────────────────────────────────────────────────────────
# RING-BUFFER LOGGER
# ─────────────────────────────────────────────────────────────────────────────

class SentinelLogger:
    """
    Thread-safe in-memory logger with a fixed-size ring buffer.
    Provides structured log records for the /sentinel/logs REST endpoint.
    """

    def __init__(self, max_records: int = 2_000):
        self._buffer: deque[LogRecord] = deque(maxlen=max_records)
        self._lock = threading.Lock()

    def _emit(self, level: str, source: str, message: str, context: Optional[dict] = None):
        record = LogRecord(
            timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            level=level,
            source=source,
            message=message,
            context=context,
        )
        with self._lock:
            self._buffer.append(record)
        # Also print to stdout for container / dev visibility
        print(str(record))

    # ── Convenience methods ───────────────────────────────────────────────────

    def info(self, source: str, message: str, context: Optional[dict] = None):
        self._emit(LogLevel.INFO, source, message, context)

    def warn(self, source: str, message: str, context: Optional[dict] = None):
        self._emit(LogLevel.WARN, source, message, context)

    def block(self, source: str, message: str, context: Optional[dict] = None):
        self._emit(LogLevel.BLOCK, source, message, context)

    def passthrough(self, source: str, message: str, context: Optional[dict] = None):
        self._emit(LogLevel.PASS, source, message, context)

    def error(self, source: str, message: str, context: Optional[dict] = None):
        self._emit(LogLevel.ERROR, source, message, context)

    # ── Query interface ───────────────────────────────────────────────────────

    def get_logs(
        self,
        level_filter: Optional[str] = None,
        limit: int = 200,
        as_dict: bool = True,
    ) -> list:
        """
        Retrieve recent log records.

        Args:
            level_filter: If set, only return records at or above this level.
                          e.g. "WARN" returns WARN + BLOCK + ERROR
            limit:        Maximum number of records to return (newest first).
            as_dict:      If True, return list of dicts; else list of LogRecord.

        Returns:
            List of log records (newest first).
        """
        with self._lock:
            all_records = list(self._buffer)

        # Filter by level
        if level_filter:
            min_order = _LEVEL_ORDER.get(level_filter.upper(), 0)
            all_records = [r for r in all_records if _LEVEL_ORDER.get(r.level, 0) >= min_order]

        # Newest first, limited
        result = list(reversed(all_records))[:limit]

        if as_dict:
            return [r.to_dict() for r in result]
        return result

    def clear(self):
        """Clear all logs from the buffer."""
        with self._lock:
            self._buffer.clear()

    @property
    def record_count(self) -> int:
        with self._lock:
            return len(self._buffer)


# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL SINGLETON
# ─────────────────────────────────────────────────────────────────────────────

# Import this instance anywhere in the project for consistent logging
sentinel_logger = SentinelLogger(max_records=2_000)
