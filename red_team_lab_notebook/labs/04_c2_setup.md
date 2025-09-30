# Lab 04 — C2 Framework Setup (Sliver/Mythic) — Lab-only, defensive-aware

**Goal:** Install an open-source C2 (Sliver or Mythic) in a contained lab to practice telemetry and detection. **Do not** use C2 infra outside your lab.

## Install (example: Sliver)
Follow project docs for the latest install steps. High-level:
1. Provision a dedicated VM (separate from attack VMs) to host the C2 server.
2. Install dependencies (Docker / docker-compose) and follow the Sliver quickstart.
3. Generate listeners on non-standard ports and test callbacks from lab agents (only lab agents you control).

## Detection exercise
- Configure Suricata/Zeek to monitor the C2 server and the victim network. Generate alerts for beacon intervals, unusual User-Agents, and long-lived TCP sessions.
- Create Suricata rules that match known C2 behaviors (in lab only) and test tuning to avoid false positives.

## Deliverable
- C2 deployment notes, sample Suricata rule(s) used for detection, and evidence (PCAP/logs) of a callback in lab.
