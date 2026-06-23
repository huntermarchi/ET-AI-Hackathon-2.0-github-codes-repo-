"""
KernelSentinel — Incident Response Orchestrator (SOAR)
Executes playbooks. Logs every action to SHA-256 chained JSONL audit trail.
"""
import json, hashlib, datetime, time
from pathlib import Path
from enum import Enum

class Action(Enum):
    SNAPSHOT_VM      = "snapshot_vm"
    ISOLATE_HOST     = "isolate_host"
    REVOKE_CREDENTIAL= "revoke_credential"
    BLOCK_IP         = "block_ip"
    ESCALATE_HUMAN   = "escalate_human"

PLAYBOOKS = {
    "CRITICAL": [Action.SNAPSHOT_VM, Action.ISOLATE_HOST,
                 Action.REVOKE_CREDENTIAL, Action.ESCALATE_HUMAN],
    "HIGH":     [Action.BLOCK_IP, Action.REVOKE_CREDENTIAL, Action.ESCALATE_HUMAN],
    "MEDIUM":   [Action.ESCALATE_HUMAN],
}

BLAST_GATE = 2   # require human approval if critical_assets >= this

class ResponseOrchestrator:
    def __init__(self, audit_log: str = "/var/log/ks_audit.jsonl"):
        self.audit_path = Path(audit_log)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._prev_hash = "0" * 10

    def _log(self, seq: int, action: str, target: str, result: str):
        entry = {
            "seq":       seq,
            "ts":        datetime.datetime.utcnow().isoformat() + "Z",
            "action":    action,
            "target":    target,
            "result":    result,
            "prev_hash": self._prev_hash,
        }
        entry_str       = json.dumps(entry, sort_keys=True)
        entry["hash"]   = hashlib.sha256(entry_str.encode()).hexdigest()[:10]
        self._prev_hash = entry["hash"]
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        print(f"[audit] seq={seq:02d} {action:20s} {target:25s} -> {result}")
        return entry

    def _dispatch(self, action: Action, alert: dict) -> str:
        host = alert["host"]
        time.sleep(0.1)   # simulate API round-trip
        dispatch = {
            Action.SNAPSHOT_VM:       f"snap-{datetime.datetime.utcnow():%Y%m%d-%H%M%S}",
            Action.ISOLATE_HOST:      f"ACK: {host} -> VLAN-99 quarantine",
            Action.REVOKE_CREDENTIAL: f"ACK: 3 sessions revoked on {host}",
            Action.BLOCK_IP:          f"ACK: firewall rule injected",
            Action.ESCALATE_HUMAN:    f"ACK: PagerDuty P1 fired",
        }
        return dispatch.get(action, "UNKNOWN")

    def execute(self, alert: dict, blast: dict) -> list:
        severity = alert["severity"]
        playbook = PLAYBOOKS.get(severity, [])
        log      = []
        seq      = 1

        for action in playbook:
            critical_count = len(blast.get("critical_assets", []))
            if action == Action.ISOLATE_HOST and critical_count >= BLAST_GATE:
                entry = self._log(seq, "HUMAN_GATE", alert["host"],
                                  f"SUSPENDED: critical_assets={critical_count}")
                log.append(entry)
                seq += 1
                break

            result = self._dispatch(action, alert)
            entry  = self._log(seq, action.value, alert["host"], result)
            log.append(entry)
            seq += 1

        return log

if __name__ == "__main__":
    from graph_agent import AttackGraphAgent
    sample_alert = {
        "alert_id": "ALT-001", "host": "gov-app-srv-04",
        "syscall": "openat", "sigma": 6.2, "severity": "CRITICAL",
        "ttp_hint": "T1083 File and Directory Discovery",
    }
    agent  = AttackGraphAgent()
    blast  = agent.blast_radius("gov-app-srv-04")
    orch   = ResponseOrchestrator(audit_log="./ks_audit.jsonl")
    result = orch.execute(sample_alert, blast)
    print(f"\n[orchestrator] {len(result)} actions logged")
