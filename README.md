# KernelSentinel
### Autonomous Cyber Resilience for Critical National Infrastructure
**ET AI Hackathon 2026 — Problem Statement #7**

---

## Team
| | |
|---|---|
| **Name** | Aayushman |
| **Institute** | IIT Jammu (M.Tech CS, Roll: 2024PCS0123) |
| **Industry** | Manager M1, ICICI Cybersecurity |
| **Supervisor** | Dr. Samaresh Bera, Dr. Shaifu Gupta |

---

## One-line pitch
> eBPF kernel-level behavioural baselining + 5-agent AI mesh that detects APT campaigns in **43 seconds** vs the industry-average **21-day MTTD** — no signatures required.

---

## Architecture
```
Data Sources (kernel logs, NetFlow, EDR, OT/SCADA, CERT-In feeds)
        ↓
eBPF Telemetry Engine  [bpftrace · zero-copy ring buffer · per-process baseline]
        ↓
AI Agent Mesh
  ├── Agent 1: Anomaly Detector     (σ-deviation scoring, UEBA)
  ├── Agent 2: ATT&CK RAG           (MITRE ATT&CK v14 + CERT-In corpus)
  ├── Agent 3: Attack Graph         (blast radius, lateral movement prediction)
  ├── Agent 4: SOAR Orchestrator    (playbook executor + human gate)
  └── Agent 5: SOC Copilot          (Claude Sonnet 4.6 chat interface)
        ↓
Outputs: SOC Dashboard · Incident Report · CERT-In API · Audit Trail
```

---

## Quickstart

```bash
# 1. Clone
git clone https://github.com/aayushman/kernelsentinel
cd kernelsentinel

# 2. Install dependencies
pip install -r requirements.txt

# 3. Start eBPF probe (requires root + Linux kernel 5.8+)
sudo bpftrace probes/syscall_monitor.bt | python3 agents/baseline_engine.py

# 4. Ingest ATT&CK corpus into vector DB
python3 agents/rag_agent.py --ingest ./corpus/

# 5. Start services
docker-compose up -d          # Neo4j + ChromaDB + Redis

# 6. Run orchestrator
python3 main.py

# 7. SOC Dashboard
cd frontend && npm install && npm run dev   # http://localhost:3000

# 8. Inject demo attack (CICIDS2017 APT29 pattern)
python3 tools/inject_attack.py --dataset cicids2017 --attack APT29
```

---

## Demo Results (APT29 trace injection)

| Metric | Baseline SOC | KernelSentinel |
|---|---|---|
| MTTD | 21 days | **43 seconds** |
| MTTR (auto) | 4 hours | **46 seconds** |
| Host isolation | Manual, hours | **5 seconds** |
| Cred revocation | Manual, 30 min | **2 seconds** |
| Audit trail | Manual log | **100%, SHA-256 chained** |
| Human gate decisions | All manual | **1 / 6 actions** |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Telemetry | eBPF / bpftrace 0.20.2 |
| Anomaly ML | Isolation Forest + σ-scoring (scikit-learn) |
| RAG | LlamaIndex + ChromaDB |
| Graph AI | NetworkX + Neo4j 5.15 |
| LLM | Claude Sonnet 4.6 (Anthropic API) |
| SOAR | Custom Python orchestrator |
| Frontend | React + D3.js + WebSocket |
| Datasets | CICIDS2017, UNSW-NB15, MITRE ATT&CK STIX v14 |

---

## Datasets
- [CICIDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) — IDS attack traces
- [UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) — Network intrusion
- [MITRE ATT&CK STIX v14](https://github.com/mitre/cti) — Threat intelligence corpus
- [CERT-In Advisories](https://www.cert-in.org.in) — India-specific threat intel

---

## Judging Criteria Alignment

| Criterion | Weight | Our response |
|---|---|---|
| Innovation | 25% | eBPF kernel telemetry — no team has thesis benchmark data backing this |
| Business Impact | 25% | 15120× MTTD improvement; targets AIIMS/CBSE-class incidents |
| Technical Excellence | 20% | 5-agent mesh, ATT&CK RAG, live σ-scoring, SHA-256 audit chain |
| Scalability | 15% | eBPF zero-overhead on untraced processes; horizontal agent mesh |
| User Experience | 15% | SOC Copilot chat + dashboard; 46-second demo |

---

## Docs
- `docs/kernelsentinel.pdf` — Full solution document
- `docs/kernelsentinel_results.pdf` — IEEE-format demo run results
- `docs/architecture.png` — Architecture diagram
