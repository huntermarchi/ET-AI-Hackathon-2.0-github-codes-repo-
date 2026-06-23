"""
KernelSentinel — Main Entry Point
Wires all agents together: eBPF stream -> anomaly -> RAG -> graph -> SOAR -> copilot
"""
import sys, json, os, threading
from agents.baseline_engine import BaselineEngine, parse_bpftrace_line
from agents.graph_agent     import AttackGraphAgent
from agents.orchestrator    import ResponseOrchestrator

ANTHROPIC_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
RAG_ENABLED   = bool(ANTHROPIC_KEY)

def run(stream=sys.stdin, host="gov-app-srv-04"):
    engine = BaselineEngine(host=host)
    graph  = AttackGraphAgent()
    orch   = ResponseOrchestrator(audit_log="./ks_audit.jsonl")

    if RAG_ENABLED:
        from agents.rag_agent import ATTACKRAGAgent
        rag = ATTACKRAGAgent(corpus_path="./corpus")
    else:
        rag = None
        print("[main] ANTHROPIC_API_KEY not set — RAG disabled, anomaly detection active")

    print(f"[main] KernelSentinel started | host={host} | RAG={'ON' if rag else 'OFF'}")

    for line in stream:
        parsed = parse_bpftrace_line(line)
        if not parsed:
            continue
        syscall, proc, pid, count = parsed
        alert = engine.ingest(proc, syscall, count)
        if not alert:
            continue

        alert_dict = {
            "alert_id": alert.alert_id, "host": alert.host,
            "process": alert.process,   "syscall": alert.syscall,
            "sigma": alert.sigma,       "severity": alert.severity,
            "ttp_hint": alert.ttp_hint,
            "baseline_rate": alert.baseline_rate,
            "observed_rate": alert.observed_rate,
        }

        print(f"\n{'='*60}")
        print(f"[alert] {alert.alert_id} | {alert.severity} | {alert.host} | "
              f"{alert.syscall} +{alert.sigma}σ | {alert.ttp_hint}")

        blast = graph.blast_radius(host)
        graph.mark_compromised(host)

        if rag:
            analysis = rag.analyse(alert_dict)
            print(f"[rag]   {analysis['analysis'][:200]}...")

        actions = orch.execute(alert_dict, blast)
        print(f"[soar]  {len(actions)} actions logged")

if __name__ == "__main__":
    run()
