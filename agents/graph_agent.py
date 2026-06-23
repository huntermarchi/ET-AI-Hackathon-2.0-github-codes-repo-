"""
KernelSentinel — Attack Graph Agent
Maintains live asset graph, predicts lateral movement, computes blast radius.
"""
import json
import networkx as nx
from itertools import islice

SAMPLE_GRAPH = {
    "nodes": [
        {"id": "gov-app-srv-04",  "criticality": 0.70, "services": ["HTTP","App"]},
        {"id": "gov-db-srv-01",   "criticality": 0.90, "services": ["MySQL"]},
        {"id": "gov-auth-srv",    "criticality": 0.95, "services": ["LDAP","Kerberos"]},
        {"id": "gov-backup-01",   "criticality": 0.80, "services": ["rsync"]},
        {"id": "gov-mail-srv-01", "criticality": 0.60, "services": ["SMTP"]},
        {"id": "gov-web-srv-02",  "criticality": 0.50, "services": ["HTTP"]},
        {"id": "gov-mon-srv",     "criticality": 0.65, "services": ["Prometheus"]},
        {"id": "gov-ci-srv",      "criticality": 0.55, "services": ["Jenkins"]},
    ],
    "edges": [
        ("gov-app-srv-04", "gov-db-srv-01"),
        ("gov-app-srv-04", "gov-web-srv-02"),
        ("gov-app-srv-04", "gov-mail-srv-01"),
        ("gov-db-srv-01",  "gov-backup-01"),
        ("gov-db-srv-01",  "gov-auth-srv"),
        ("gov-auth-srv",   "gov-backup-01"),
        ("gov-web-srv-02", "gov-mon-srv"),
        ("gov-ci-srv",     "gov-app-srv-04"),
    ],
}

class AttackGraphAgent:
    def __init__(self):
        self.G = nx.DiGraph()
        self.compromised = set()
        self._load_default()

    def _load_default(self):
        for n in SAMPLE_GRAPH["nodes"]:
            self.G.add_node(n["id"],
                            criticality=n["criticality"],
                            services=n["services"],
                            status="clean")
        for src, dst in SAMPLE_GRAPH["edges"]:
            self.G.add_edge(src, dst)

    def mark_compromised(self, node: str):
        self.compromised.add(node)
        if node in self.G:
            self.G.nodes[node]["status"] = "COMPROMISED"

    def predict_next_targets(self, origin: str, top_k: int = 5) -> list:
        if origin not in self.G:
            return []
        scores = {}
        for tgt in list(self.G.nodes):
            if tgt == origin:
                continue
            try:
                for path in islice(
                    nx.all_simple_paths(self.G, origin, tgt, cutoff=3), 200
                ):
                    for node in path[1:]:
                        scores[node] = scores.get(node, 0) + \
                                       self.G.nodes[node].get("criticality", 0.5)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                pass
        return sorted(scores, key=scores.get, reverse=True)[:top_k]

    def blast_radius(self, origin: str) -> dict:
        if origin not in self.G:
            return {}
        reachable = list(nx.descendants(self.G, origin))
        critical  = [n for n in reachable
                     if self.G.nodes[n].get("criticality", 0) > 0.7]
        return {
            "origin":           origin,
            "total_reachable":  len(reachable),
            "reachable_nodes":  reachable,
            "critical_assets":  critical,
            "estimated_blast":  "HIGH" if len(critical) >= 2 else "MEDIUM",
        }

    def report(self, origin: str) -> dict:
        self.mark_compromised(origin)
        targets = self.predict_next_targets(origin)
        blast   = self.blast_radius(origin)
        return {
            "compromised": origin,
            "predicted_targets": [
                {"host": t,
                 "criticality": self.G.nodes[t].get("criticality"),
                 "services":    self.G.nodes[t].get("services")}
                for t in targets
            ],
            "blast_radius": blast,
            "human_gate_required": len(blast.get("critical_assets", [])) >= 2,
        }

if __name__ == "__main__":
    import sys
    origin = sys.argv[1] if len(sys.argv) > 1 else "gov-app-srv-04"
    agent  = AttackGraphAgent()
    print(json.dumps(agent.report(origin), indent=2))
