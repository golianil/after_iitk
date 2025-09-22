
# SEG_90day_plan.md
This is the 90-day detailed weekly checklist and tasks. Follow these steps in sequence; each week has concrete deliverables.

## Overview
Goal: From basic Python/C/C++ and IIT Kanpur training to practical red-team/pentesting competence and portfolio-ready deliverables in 90 days.

### Week 0 (Preparation — weekend)
- [ ] Provision hardware/VM host and install VirtualBox or VMware.
- [ ] Create a GitHub private repo `SEG-Labs`.
- [ ] Download Kali ISO, Windows Server ISO, Windows client ISO, Ubuntu server ISO.
- [ ] Optional: Create AWS free-tier account (use separate billing or sandbox).
- Deliverable: VM snapshots saved and `SEG-Labs` repo created.

---

## Weeks 1–2: Lab & Python focus
**Goals:** Lab ready; robust Python parsing tooling; one HTB/TryHackMe beginner path completed.
- Tasks:
  - [ ] Build VMs: Kali, Windows Server (DC), Windows client, Ubuntu (ELK/Splunk).
  - [ ] Install tooling on Kali: Python3, pip, pwntools, scapy, pefile, yara-python, frida.
  - [ ] Write `seg_eml_parser.py`:
    - CLI: `seg_eml_parser.py --eml path --out features.json`
    - Extract: headers (decoded), body text, attachments metadata (name, size, type), URLs, SPF/DKIM check flags (if present).
  - [ ] Unit tests for parser (pytest).
  - [ ] Complete 3 beginner TryHackMe rooms (Linux fundamentals, Web basics, Intro to Pentesting).
- Deliverables:
  - `seg_eml_parser.py` in repo, test cases, and 3 room certificates/screenshots.

---

## Weeks 3–4: C fundamentals & simple exploit dev
**Goals:** Understand memory layout and build simple PoCs.
- Tasks:
  - [ ] Build small C programs: `vuln_stack.c`, `vuln_format.c`.
  - [ ] Compile with/without mitigations; practice `gdb` debugging.
  - [ ] Create exploit for `vuln_stack.c` that spawns `/bin/sh` on a Linux VM.
  - [ ] Begin pwnable.kr beginner problems (2–3).
- Deliverables:
  - Exploit scripts (pwntools), writeup: `exploit_vuln_stack.md`.

---

## Weeks 5–6: Reverse engineering & web pentest basics
**Goals:** Reverse a small stripped binary; web pentest with Burp.
- Tasks:
  - [ ] Use Ghidra on a stripped C binary; map functions to behavior.
  - [ ] Practice with x64dbg on Windows binary (if available).
  - [ ] Complete Web app labs: SQLi and XSS (DVWA or WebGoat locally).
  - [ ] Write a Burp macro to automate a repeated action.
- Deliverables:
  - RE writeup `reversed_binary_analysis.md`; Burp macros saved.

---

## Weeks 7–10: Active Directory & Post‑exploitation
**Goals:** Build AD lab and perform an end-to-end simulated engagement.
- Tasks:
  - [ ] Configure Windows Server as Domain Controller; create a few users and groups.
  - [ ] Deploy BloodHound and ingestors; map relationships.
  - [ ] Use a simulated initial access (phishing/email lured VM or local exploit).
  - [ ] Perform privilege escalation, lateral movement, demonstrate exfil to a controlled SMB share or S3 bucket.
  - [ ] Create Splunk queries to detect lateral movement patterns and Mimikatz-like behavior.
- Deliverables:
  - Full AD engagement writeup: `ad_full_engagement.md` including MITRE ATT&CK mapping and Splunk detections.

---

## Weeks 11–13: Cloud & Kubernetes basics
**Goals:** Practice cloud misconfigurations and K8s RBAC issues.
- Tasks:
  - [ ] Set up LocalStack or small AWS lab; create S3 bucket, IAM users/roles.
  - [ ] Simulate misconfig: public S3 with sensitive files, excessive IAM permissions.
  - [ ] Practice EC2 metadata abuse (IMDSv1 vs v2).
  - [ ] Deploy minikube and simulate pod with hostPath or privileged container; show escalation vectors.
- Deliverables:
  - Cloud misconfig report `cloud_misconfig.md`; K8s RBAC demo with remediation advice.

---

## Weeks 14–18: Advanced topics & portfolio finalization
**Goals:** Polish 3–6 writeups, finalize portfolio, start certification prep.
- Tasks:
  - [ ] Choose 3 strongest projects; finalize writeups and sanitize PoCs for public sharing.
  - [ ] Prepare for OSCP/GPEN: craft study schedule (labs, buffer overflow exercises).
  - [ ] Record short video demos (screen capture) for each project (2–4 minutes).
- Deliverables:
  - `portfolio.zip` with PDFs, PoC code (redacted), and videos.

---

# Hints & Tips
- Always snapshot VM state before attempting destructive actions.
- Maintain an attack log in your repo: date/time, commands, output, remediation notes.
- Use a dedicated, isolated network for malware analysis and external-facing tests.
- Keep a weekly retrospective: what you learned, what to fix next week.

# End of 90-day plan
