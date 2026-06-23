"""
KernelSentinel — Anomaly Detection Engine
Consumes bpftrace stdout, maintains 7-day rolling baseline,
emits JSON alerts to stdout / message bus.
"""
import sys, json, time, re, numpy as np
from collections import defaultdict, deque
from dataclasses import dataclass, asdict

TTP_MAP = {
    "openat":  ("T1083", "File and Directory Discovery"),
    "read":    ("T1005", "Data from Local System"),
    "write":   ("T1560", "Archive Collected Data"),
    "connect": ("T1046", "Network Service Scanning"),
    "execve":  ("T1059", "Command and Scripting Interpreter"),
    "futex":   ("T1055", "Process Injection"),
    "close":   ("T1014", "Rootkit"),
}

@dataclass
class Alert:
    alert_id: str
    timestamp: str
    host: str
    process: str
    syscall: str
    baseline_rate: float
    observed_rate: int
    sigma: float
    ttp_hint: str
    severity: str

class BaselineEngine:
    WINDOW    = 7 * 24 * 360   # 10-second buckets, 7 days
    THRESHOLD = 3.0
    _seq      = 0

    def __init__(self, host: str = "localhost"):
        self.host = host
        self.windows = defaultdict(
            lambda: defaultdict(lambda: deque(maxlen=self.WINDOW))
        )

    def ingest(self, proc: str, syscall: str, count: int):
        w = self.windows[proc][syscall]
        w.append(count)
        if len(w) < 60:
            return None
        arr   = np.array(w)
        mean  = arr.mean()
        std   = arr.std() or 1.0
        sigma = (count - mean) / std
        if abs(sigma) < self.THRESHOLD:
            return None
        BaselineEngine._seq += 1
        tid, tname = TTP_MAP.get(syscall, ("T????", "Unknown"))
        sev = ("CRITICAL" if abs(sigma) >= 6 else
               "HIGH"     if abs(sigma) >= 4 else "MEDIUM")
        return Alert(
            alert_id      = f"ALT-{BaselineEngine._seq:04d}",
            timestamp     = time.strftime("%Y-%m-%d %H:%M:%S"),
            host          = self.host,
            process       = proc,
            syscall       = syscall,
            baseline_rate = round(mean, 1),
            observed_rate = count,
            sigma         = round(sigma, 1),
            ttp_hint      = f"{tid} {tname}",
            severity      = sev,
        )

def parse_bpftrace_line(line: str):
    """Parse bpftrace print(@map) output: @openat[comm, pid]: count"""
    m = re.match(r'@(\w+)\[(.+?),\s*(\d+)\]:\s*(\d+)', line.strip())
    if m:
        return m.group(1), m.group(2).strip(), int(m.group(3)), int(m.group(4))
    return None

if __name__ == "__main__":
    import os
    engine = BaselineEngine(host=os.environ.get("KS_HOST", "localhost"))
    print("[baseline_engine] started — reading bpftrace stream", flush=True)
    for line in sys.stdin:
        parsed = parse_bpftrace_line(line)
        if not parsed:
            continue
        syscall, proc, _, count = parsed
        alert = engine.ingest(proc, syscall, count)
        if alert:
            print(json.dumps(asdict(alert)), flush=True)
