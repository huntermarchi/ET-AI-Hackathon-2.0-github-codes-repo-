"""
KernelSentinel — SOC Copilot
Multi-turn analyst chat interface powered by Claude Sonnet 4.6.
"""
import json, anthropic

SYSTEM = """You are KernelSentinel SOC Copilot, an AI assistant for security analysts
defending Indian critical national infrastructure.

You have access to:
- Live anomaly alerts with sigma-deviation scores (eBPF kernel telemetry)
- ATT&CK threat intelligence analysis per alert
- Attack graph with blast radius and predicted lateral movement targets
- Full SOAR audit log of every automated action taken

Rules:
- Always cite alert IDs (ALT-XXX)
- Reference MITRE ATT&CK technique IDs
- Be concise and actionable — analysts are under time pressure
- Flag if human gate approval is pending
- Recommend CERT-In reporting if incident is confirmed"""

class SOCCopilot:
    def __init__(self):
        self.client  = anthropic.Anthropic()
        self.history = []
        self.context = {}

    def inject_context(self, alerts=None, analyses=None,
                       blast=None, audit_log=None):
        self.context = {
            "alerts":    alerts    or [],
            "analyses":  analyses  or [],
            "blast":     blast     or {},
            "audit_log": audit_log or [],
        }

    def chat(self, user_message: str) -> str:
        system = SYSTEM + f"\n\nCurrent incident context (JSON):\n{json.dumps(self.context, indent=2)}"
        self.history.append({"role": "user", "content": user_message})
        response = self.client.messages.create(
            model      = "claude-sonnet-4-6",
            max_tokens = 1000,
            system     = system,
            messages   = self.history,
        )
        reply = response.content[0].text
        self.history.append({"role": "assistant", "content": reply})
        return reply

def demo_session():
    copilot = SOCCopilot()
    copilot.inject_context(
        alerts=[
            {"alert_id":"ALT-001","host":"gov-app-srv-04","syscall":"openat",
             "sigma":6.2,"severity":"CRITICAL","ttp_hint":"T1083"},
            {"alert_id":"ALT-002","host":"gov-app-srv-04","syscall":"read",
             "sigma":8.1,"severity":"CRITICAL","ttp_hint":"T1005"},
            {"alert_id":"ALT-003","host":"gov-db-srv-01","syscall":"connect",
             "sigma":5.4,"severity":"HIGH","ttp_hint":"T1046"},
        ],
        blast={
            "origin":"gov-app-srv-04","total_reachable":5,
            "critical_assets":["gov-auth-srv","gov-db-srv-01","gov-backup-01"],
            "estimated_blast":"HIGH","human_gate_required": True,
        },
        audit_log=[
            "snapshot_vm: gov-app-srv-04 -> snap-20260622-031314",
            "isolate_host: gov-app-srv-04 -> VLAN-99",
            "revoke_credential: 3 sessions killed",
            "escalate_human: PagerDuty P1 fired",
            "HUMAN_GATE: gov-db-srv-01 isolation SUSPENDED",
        ]
    )

    questions = [
        "Why was ALT-001 triggered?",
        "Are the alerts on both hosts related?",
        "What actions have been taken automatically?",
        "What should I do right now? Give me a prioritised list.",
    ]

    print("=" * 60)
    print("KernelSentinel SOC Copilot — Demo Session")
    print("=" * 60)
    for q in questions:
        print(f"\nAnalyst > {q}")
        print(f"Copilot > {copilot.chat(q)}")
        print("-" * 40)

if __name__ == "__main__":
    demo_session()
