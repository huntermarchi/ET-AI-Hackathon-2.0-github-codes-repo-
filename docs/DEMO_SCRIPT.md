# KernelSentinel — 3-Minute Demo Script
**ET AI Hackathon 2026 | PS#7 | Aayushman | IIT Jammu**

---

## Setup (before recording)
```bash
# Terminal 1 — have this ready but NOT running
python3 tools/inject_attack.py --attack APT29 --warmup 5 --speed 0.3 | python3 main.py

# Terminal 2 — SOC Copilot ready
python3 agents/soc_copilot.py

# Browser — architecture diagram open (docs/kernelsentinel.pdf page 3)
```

---

## Script (speak naturally, ~3 min)

### [0:00–0:25] Hook
> "India's AIIMS Delhi was offline for 2 weeks after a ransomware attack.
> The security team had all the data — they just couldn't act on it fast enough.
> KernelSentinel fixes that. It detects APT attacks in 43 seconds, not 21 days."

*[Show architecture diagram — point to each layer]*

> "We use eBPF — the same kernel tracing technology from my M.Tech thesis —
> to watch every syscall on every process, in real time, with zero overhead."

---

### [0:25–1:00] Live Demo — Attack Injection
*[Switch to Terminal 1, run the command]*

```bash
python3 tools/inject_attack.py --attack APT29 | python3 main.py
```

> "I'm injecting an APT29-pattern attack trace — same technique used in the
> 2024 CERT-In advisory for Indian government infrastructure attacks."

*[Wait for first ALERT to appear — point to it]*

> "ALT-001. openat() syscall spiked to 847 per second —
> that's 6.2 standard deviations above the 7-day baseline.
> Our eBPF probe caught it 43 seconds after the attack started."

*[Wait for more alerts]*

> "ALT-002, ALT-003. The anomaly engine detected a compound attack chain —
> T1083 File Discovery, then T1005 Data Collection, then T1046 lateral movement.
> Three TTPs on two hosts, correlated automatically."

---

### [1:00–1:40] SOAR Response
*[Point to orchestrator output]*

> "The SOAR orchestrator immediately took 5 actions — all in under 2 seconds each:
> forensic snapshot, host isolation into quarantine VLAN,
> credential revocation, firewall rule, PagerDuty P1 alert."

> "Notice here — the system hit a human gate.
> The blast radius analysis showed 3 critical assets downstream.
> gov-auth-srv is the government LDAP server — domain-wide credentials.
> The system correctly stopped and waited for analyst approval."

---

### [1:40–2:20] SOC Copilot
*[Switch to Terminal 2]*

> "Now I ask the SOC Copilot — powered by Claude Sonnet 4.6 —
> what happened and what to do next."

*[Type: "Why was ALT-001 triggered?"]*
*[Wait for response, read first 2 sentences aloud]*

*[Type: "What should I do right now?"]*
*[Wait for response, read prioritised list]*

> "In under 2 seconds, the copilot gives me a prioritised action list —
> approve the db-srv isolation, pull the forensic snapshot,
> check gov-auth-srv for T1078, and file the CERT-In IR report."

---

### [2:20–2:50] Numbers
*[Show results table from docs/kernelsentinel_results.pdf]*

> "The headline: 43 seconds vs 21 days industry average MTTD.
> 5 automated actions. 1 human gate decision.
> 100% SHA-256 chained audit trail — every action admissible as evidence."

> "The eBPF layer is why this is possible —
> it's not reading logs after the fact,
> it's hooked into the kernel, watching syscalls as they happen."

---

### [2:50–3:00] Close
> "KernelSentinel. eBPF-native, agent-powered, 43-second detection.
> Built for India's critical infrastructure — by someone who's spent
> the last year benchmarking eBPF at the kernel level."

---

## Recording Tips
- Use OBS or Loom (free)
- Font size: 18pt minimum in terminal
- Split screen: terminal left, PDF right
- Keep it under 50MB — 720p is fine
- Trim silences in any video editor
