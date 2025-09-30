# Lab 05 — Detection, Logging, and Purple-Team Exercises

**Goal:** Build detection rules, ingest telemetry, and measure detection coverage.

## Stack suggestions (local lab)
- Zeek (for network logs) — capture conn.log, http.log, dns.log.
- Suricata (IDS) — EVE JSON output ingested into ELK or Security Onion.
- Security Onion (optional) — prebuilt distro for IDS + sysmon + Elastic stack.

## Example detection tasks
1. **Suricata rule** (lab-only example):
```
alert http any any -> any any (msg:"LAB - HTTP suspicious User-Agent"; http.user_agent; content:"sqlmap"; sid:1000001; rev:1;)
```
2. **Simple Sigma rule** (YAML) to detect suspicious cmd.exe invocations in Windows Sysmon (lab-only example):
```yaml
title: Suspicious Cmd Execution
logsource:
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 1
    Image|endswith: "\cmd.exe"
  condition: selection
level: medium
```
3. Generate activity in lab (e.g., run benign scanning and a simulated beacon) and measure detection results, tune rules to reduce false positives.

## Deliverable
- Two tuned detection rules (Suricata + Sigma), test PCAP, and a short analysis of detection performance and false positives.
