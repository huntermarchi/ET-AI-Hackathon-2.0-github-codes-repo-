"""
KernelSentinel — Demo Attack Injector
Simulates APT29 attack pattern without needing real malware.
Outputs bpftrace-format stream to stdout for the baseline engine.
"""
import time, random, argparse, sys

BASELINE = {
    "openat":  (12, 3),    # (mean, std) per 10s window
    "read":    (340, 40),
    "write":   (180, 25),
    "connect": (8,  2),
    "execve":  (0,  0.5),
    "futex":   (890, 80),
}

APT29_ATTACK = [
    # (minute_offset, host, syscall, count, note)
    (0,   "gov-app-srv-04", "openat",  847,   "T1083 file enumeration"),
    (0,   "gov-app-srv-04", "read",    12400, "T1005 data collection"),
    (0,   "gov-app-srv-04", "execve",  3,     "find / -name *.conf"),
    (0,   "gov-app-srv-04", "write",   2100,  "T1560 staging"),
    (0,   "gov-db-srv-01",  "connect", 203,   "T1046 lateral port scan"),
    (2,   "gov-db-srv-01",  "futex",   1240,  "T1055 injection attempt"),
    (5,   "gov-auth-srv",   "openat",  340,   "T1078 credential access"),
]

def emit_baseline(host: str, seconds: int = 60):
    """Emit normal baseline traffic for warm-up."""
    for _ in range(seconds // 10):
        for syscall, (mean, std) in BASELINE.items():
            count = max(0, int(random.gauss(mean, std)))
            proc  = "nginx" if syscall in ("read","write") else "systemd"
            print(f'@{syscall}[{proc}, 1234]: {count}', flush=True)
        time.sleep(0.05)   # fast-forward in demo mode

def emit_attack(scenario: list, speed: float = 0.5):
    """Emit attack pattern."""
    for t_offset, host, syscall, count, note in scenario:
        print(f'# ATTACK t+{t_offset}min {host} -- {note}', flush=True)
        print(f'@{syscall}[python3, 41203]: {count}', flush=True)
        time.sleep(speed)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KernelSentinel demo attack injector")
    parser.add_argument("--dataset", default="cicids2017")
    parser.add_argument("--attack",  default="APT29")
    parser.add_argument("--warmup",  type=int, default=60,
                        help="Baseline warmup seconds")
    parser.add_argument("--speed",   type=float, default=0.5,
                        help="Seconds between attack events")
    args = parser.parse_args()

    print(f"[inject] Dataset={args.dataset} Attack={args.attack}", file=sys.stderr)
    print(f"[inject] Emitting {args.warmup}s baseline warmup...", file=sys.stderr)
    emit_baseline("gov-app-srv-04", args.warmup)

    print(f"[inject] Injecting {args.attack} attack pattern...", file=sys.stderr)
    emit_attack(APT29_ATTACK, speed=args.speed)
    print("[inject] Attack trace complete.", file=sys.stderr)
