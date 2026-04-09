import threading, datetime
from collections import deque
from dataclasses import dataclass, asdict
from typing import Optional

class LogLevel:
    INFO="INFO"; WARN="WARN"; BLOCK="BLOCK"; PASS="PASS"; ERROR="ERROR"

_LEVEL_ORDER = {"INFO":0,"PASS":1,"WARN":2,"BLOCK":3,"ERROR":4}

@dataclass
class LogRecord:
    timestamp: str; level: str; source: str; message: str; context: Optional[dict]=None
    def to_dict(self): return asdict(self)
    def __str__(self):
        ctx=f" | ctx={self.context}" if self.context else ""
        return f"[{self.timestamp}] [{self.level:>5}] {self.source} — {self.message}{ctx}"

class SentinelLogger:
    def __init__(self, max_records=2000):
        self._buffer=deque(maxlen=max_records); self._lock=threading.Lock()
    def _emit(self, level, source, message, context=None):
        record=LogRecord(timestamp=datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]+"Z",level=level,source=source,message=message,context=context)
        with self._lock: self._buffer.append(record)
    def info(self,s,m,c=None): self._emit("INFO",s,m,c)
    def warn(self,s,m,c=None): self._emit("WARN",s,m,c)
    def block(self,s,m,c=None): self._emit("BLOCK",s,m,c)
    def passthrough(self,s,m,c=None): self._emit("PASS",s,m,c)
    def error(self,s,m,c=None): self._emit("ERROR",s,m,c)
    def get_logs(self, level_filter=None, limit=200, as_dict=True):
        with self._lock: all_r=list(self._buffer)
        if level_filter:
            min_o=_LEVEL_ORDER.get(level_filter.upper(),0)
            all_r=[r for r in all_r if _LEVEL_ORDER.get(r.level,0)>=min_o]
        result=list(reversed(all_r))[:limit]
        return [r.to_dict() for r in result] if as_dict else result
    def clear(self):
        with self._lock: self._buffer.clear()
    @property
    def record_count(self):
        with self._lock: return len(self._buffer)

sentinel_logger = SentinelLogger(max_records=2000)
